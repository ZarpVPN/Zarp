using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Zarp.Core;

static partial class Program
{
    static readonly string[] RegistrationTestAddresses = { "162.159.137.105", "2606:4700:7::a29f:8969" };
    static RunResult MissingWarpRegistration() => new RunResult { ExitCode = 1, Output = "Error: MissingRegistration" };
    static RunResult BlockedWarpRegistration() => new RunResult { ExitCode = 1, Output = "Error: ConnectivityError: error sending request: connection reset" };

    static MockWarp ProtectedRegistrationMock(params Strategy[] strategies)
    {
        var mock = new MockWarp(strategies);
        SetPrivate(mock.Engine.Warp, "RegistrationRetryDelayMs", 0);
        UseSleepingWinws(mock.Engine, Path.Combine(_data, "registration-winws"));
        SetPrivate(mock.Engine.Zapret, "SettleDelayMs", 10);
        SetPrivate(mock.Engine, "RegistrationAddresses", (Func<CancellationToken, Task<IReadOnlyList<string>>>)(ct =>
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<string>>(RegistrationTestAddresses);
        }));
        return mock;
    }

    static Task<bool> EnsureProtectedRegistration(Engine engine, CancellationToken ct = default) =>
        (Task<bool>)typeof(Engine).GetMethod("EnsureWarpRegistrationAsync", PrivateInstance).Invoke(engine, new object[] { ct, null });

    static void TestWarpRegistrationApiConfig() => WithEmbeddedZapret(zapret =>
    {
        var api = typeof(Warp).Assembly.GetType("Zarp.Core.WarpRegistrationApi");
        var addresses = (string[])api.GetField("PinnedAddresses", PrivateStatic).GetValue(null);
        var tls = StrategyCatalog.BuiltInStrategies.Where(s => s.Transport == WarpTransport.MasqueH2).ToArray();
        foreach (var strategy in tls)
        {
            var args = zapret.BuildRegistrationArgs(strategy, addresses);
            Check(args.Contains("--wf-tcp-out=443") && !args.Any(a => a.StartsWith("--wf-udp") || a.Contains("1-65535")), "Registration only intercepts HTTPS, even when the tunnel uses QUIC");
            string filter = args.Single(a => a.StartsWith("--wf-raw-filter="));
            Check(addresses.All(ip => filter.Contains("DstAddr==" + ip) && filter.Contains("SrcAddr==" + ip)) && !filter.Contains("162.159.192"),
                  "The filter covers API IPv4 and IPv6 in both directions, independently of tunnel endpoints");
            Check(args.Any(a => a.StartsWith("--hostlist-domains=") && a.Contains("api.cloudflareclient.com") && a.Contains("api.devices.cloudflare.com")),
                  "Shared IP addresses still have a Cloudflare API hostname filter");
            var run = DryRun(zapret, zapret.BuildRegistrationConfig(strategy, addresses));
            Check(run.StartError == null && !run.TimedOut && run.Code == 0 && run.Stdout.Contains("command line parameters verified"),
                  strategy.Id + ": the embedded winws2 must accept the registration configuration\n" + run.Describe());
        }
        string native = SavedFilter(zapret, zapret.BuildRegistrationConfig(tls[0], addresses), "registration-api");
        Check(native.Contains("tcp.DstPort == 443") && native.Contains("tcp.SrcPort == 443") && !native.Contains("udp.DstPort"), "The native filter builder preserves the HTTPS port and protocol");
        if (Environment.Is64BitProcess)
            Check(WinDivertSyntaxError(Path.Combine(zapret.Dir, "WinDivert.dll"), native) == null, "WinDivert accepts the complete API filter without opening its driver");
        foreach (string bad in new[] { "", "api.cloudflareclient.com", "203.0.113.7 or true", "127.0.0.1", "10.0.0.1", "0.0.0.0", "::", "fd00::1" })
            Check(Catch(() => zapret.BuildRegistrationArgs(tls[0], new[] { bad })) is ArgumentException, "Unsafe or local addresses cannot widen the registration filter: " + bad);
        Check(Catch(() => zapret.BuildRegistrationArgs(tls[0], new string[0])) is ArgumentException, "An empty API list cannot become an unrestricted filter");
        Check(Catch(() => zapret.BuildRegistrationArgs(StrategyCatalog.BuiltInStrategies.First(s => s.Transport == WarpTransport.MasqueH3), addresses)) is ArgumentException,
              "QUIC strategies cannot be used for registration HTTPS");
    });

    static async Task TestWarpRegistrationProtectedAsync()
    {
        var bad = Tagged("registration-first", SplitArgs, "ru");
        var good = Tagged("registration-working", SplitArgs + " --lua-desync=send", "ru");
        var excluded = Tagged("registration-other-country", SplitArgs, "cn");
        var quic = Tagged("registration-quic", SplitArgs, "ru");
        quic.Transport = WarpTransport.MasqueH3;
        var mock = ProtectedRegistrationMock(quic, bad, excluded, good);
        var engine = mock.Engine;
        engine.Config.StrategyCountry = "ru";
        engine.Config.SelectedStrategyId = bad.Id;
        var previous = new TestResult { StrategyId = bad.Id, Ok = true, Confirmed = true };
        engine.Config.Results[bad.Id] = previous;
        engine.Config.Save();
        string config = File.ReadAllText(Path.Combine(engine.DataDir, "zarp.json"));
        int attempts = 0;
        bool registered = false;
        var protectedArgs = new List<string>();
        mock.Override = cmd =>
        {
            if (cmd == "registration show") return registered ? new RunResult { Output = WarpPlusRegistration } : MissingWarpRegistration();
            if (cmd != "registration new") return null;
            attempts++;
            string args = engine.Zapret.RunningStrategyArgs();
            if (args != null)
            {
                protectedArgs.Add(args);
                Check(File.ReadAllText(Path.Combine(engine.Zapret.Dir, "zarp.cfg")).Contains("--hostlist-domains=api.cloudflareclient.com"), "Registration is protected by the API filter while the CLI command runs");
            }
            if (args == good.Args) { registered = true; return new RunResult(); }
            return BlockedWarpRegistration();
        };
        Check(await EnsureProtectedRegistration(engine), "Registration blocked directly and under the first TLS strategy succeeds under the next one");
        Check(attempts == 3 && protectedArgs.SequenceEqual(new[] { bad.Args, good.Args }), "Only the selected country's TLS strategies are tried after the direct attempt");
        Check(!engine.Zapret.Running && engine.State == EngineState.Idle, "The temporary API process stops after success");
        Check(engine.Config.SelectedStrategyId == bad.Id && ReferenceEquals(engine.Config.Results[bad.Id], previous) && engine.Config.Results.Count == 1 &&
              File.ReadAllText(Path.Combine(engine.DataDir, "zarp.json")) == config, "Registration success does not claim a working tunnel or change saved results");
        Check(!mock.Calls.Any(cmd => cmd == "connect" || cmd.Contains("delete") || cmd.StartsWith("tunnel ")), "Finding a registration strategy never connects, deletes or reconfigures the tunnel");
        Check(await EnsureProtectedRegistration(engine) && attempts == 3, "An existing WARP+ registration is reused without another strategy search");
    }

    static async Task TestWarpRegistrationProtectedFailuresAsync()
    {
        var tls = Tagged("registration-tls", SplitArgs, "ru");
        foreach (string failure in new[] { "daemon", "old", "quota", "rate" })
        {
            var mock = ProtectedRegistrationMock(tls);
            bool resolved = false;
            SetPrivate(mock.Engine, "RegistrationAddresses", (Func<CancellationToken, Task<IReadOnlyList<string>>>)(ct =>
            { resolved = true; return Task.FromResult<IReadOnlyList<string>>(RegistrationTestAddresses); }));
            mock.Override = cmd => failure == "daemon" ? new RunResult { ExitCode = 1, Output = WarpIpcTimeout }
                : cmd == "registration show" ? MissingWarpRegistration() : new RunResult { ExitCode = 1, Output = failure == "old"
                    ? "Error: Old registration is still around. Try running: warp-cli registration delete"
                    : failure == "rate" ? "HTTP 429 Too Many Requests" : "Registration denied: device quota exceeded" };
            Check(!await EnsureProtectedRegistration(mock.Engine) && !resolved && !mock.Engine.Zapret.Running,
                  "A local service failure, old registration, quota or rate limit must not start DPI trials: " + failure);
            Check(!mock.Calls.Any(cmd => cmd.Contains("delete")), "Account recovery never deletes a registration");
        }
        var exhausted = ProtectedRegistrationMock(tls, Tagged("registration-tls-2", SplitArgs + " --lua-desync=send", "ru"));
        exhausted.Override = cmd => cmd == "registration show" ? MissingWarpRegistration() : cmd == "registration new" ? BlockedWarpRegistration() : null;
        await exhausted.Engine.ConnectAsync();
        Check(exhausted.Calls.Count(cmd => cmd == "registration new") == 3 && !exhausted.Calls.Contains("connect"), "Failed API trials stop after all TLS strategies and do not run tunnel tests");
        Check(exhausted.Engine.State == EngineState.Idle && !exhausted.Engine.Zapret.Running && exhausted.Engine.Config.Results.Count == 0,
              "Exhausting registration strategies leaves no process or false tunnel results");

        var pending = RegistrationMock();
        pending.Override = cmd => cmd == "registration new" ? new RunResult { ExitCode = 1, Output = WarpIpcTimeout } : MissingWarpRegistration();
        Check(!await pending.Engine.Warp.EnsureRegisteredAsync(), "A timed-out creation remains pending when the subsequent reads still report missing");
        int beforeRetry = pending.Calls.Count;
        var retry = typeof(Warp).GetMethod("RetryRegistrationAsync", PrivateInstance);
        using (var cancel = new CancellationTokenSource(30))
        {
            bool caught = false;
            try { await (Task<bool>)retry.Invoke(pending.Engine.Warp, new object[] { cancel.Token }); }
            catch (OperationCanceledException) { caught = true; }
            Check(caught && pending.Calls.Count == beforeRetry, "The pending deadline is cancellable and sends no duplicate create command");
        }
        SetPrivate(pending.Engine.Warp, "_registrationPendingUntil", DateTime.UtcNow.AddMilliseconds(20));
        pending.Override = cmd => cmd == "registration show" ? new RunResult { Output = WarpPlusRegistration } : null;
        Check(await (Task<bool>)retry.Invoke(pending.Engine.Warp, new object[] { CancellationToken.None }) && pending.Calls.Count(cmd => cmd == "registration new") == 1,
              "A registration completed during the cooldown is read back and never recreated");

        var cancelled = ProtectedRegistrationMock(tls);
        using (var cancel = new CancellationTokenSource())
        {
            cancelled.Override = cmd =>
            {
                if (cmd == "registration show") return MissingWarpRegistration();
                if (cmd == "registration new")
                {
                    if (cancelled.Engine.Zapret.Running) cancel.Cancel();
                    return BlockedWarpRegistration();
                }
                return null;
            };
            bool caught = false;
            try { await cancelled.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey, cancel.Token); }
            catch (OperationCanceledException) { caught = true; }
            Check(caught && !cancelled.Engine.IsBusy && !cancelled.Engine.Zapret.Running && cancelled.Engine.State == EngineState.Idle,
                  "Cancelling protected registration releases the engine and stops the API process");
            Check(!cancelled.Calls.Any(cmd => cmd.StartsWith("registration license") || cmd.Contains("delete")), "Cancellation does not apply a license or delete an account");
        }
    }

    static async Task TestWarpRegistrationProtectedAccountAsync()
    {
        var mock = ProtectedRegistrationMock(Tagged("registration-account", SplitArgs, "ru"));
        bool registered = false;
        mock.Override = cmd =>
        {
            if (cmd == "registration show") return registered ? new RunResult { Output = WarpPlusRegistration } : MissingWarpRegistration();
            if (cmd == "registration new")
            {
                if (!mock.Engine.Zapret.Running) return BlockedWarpRegistration();
                registered = true;
                return new RunResult();
            }
            if (cmd.StartsWith("registration license "))
                Check(mock.Engine.Zapret.Running && File.ReadAllText(Path.Combine(mock.Engine.Zapret.Dir, "zarp.cfg")).Contains("--hostlist-domains="),
                      "The successful API strategy stays active until the WARP+ key has been applied");
            return null;
        };
        var log = new List<string>();
        Action<string> capture = line => log.Add(line);
        Log.Line += capture;
        try { Check(await mock.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unlimited, "A fresh device can register and link WARP+ through zapret2"); }
        finally { Log.Line -= capture; }
        Check(!mock.Engine.Zapret.Running && !mock.Engine.IsBusy && mock.Engine.State == EngineState.Idle, "Completing the key operation cleans up its temporary strategy");
        Check(log.All(line => !line.Contains(WarpPlusTestKey) && !line.Contains("private-device-id")) && !mock.Calls.Contains("connect"),
              "Protected registration logs expose no account details and do not start a tunnel");
        registered = false;
        var original = mock.Override;
        mock.Override = cmd =>
        {
            var result = original(cmd);
            return cmd.StartsWith("registration license ") ? new RunResult { ExitCode = 1, Output = WarpPlusTestKey + " private-device-id rejected" } : result;
        };
        Exception failure = null;
        try { await mock.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey); }
        catch (IOException e) { failure = e; }
        Check(failure != null && !failure.Message.Contains(WarpPlusTestKey) && !failure.Message.Contains("private-device-id"), "A license rejection under zapret2 also hides private CLI output");
        Check(!mock.Engine.Zapret.Running && !mock.Engine.IsBusy, "A license failure still stops its temporary API strategy");
    }

    static async Task TestWarpRegistrationProtectedConnectAsync()
    {
        var strategy = Tagged("registration-connect", SplitArgs, "ru");
        var mock = ProtectedRegistrationMock(strategy);
        bool registered = false;
        mock.Override = cmd =>
        {
            if (cmd == "registration show") return registered ? new RunResult { Output = WarpPlusRegistration } : MissingWarpRegistration();
            if (cmd != "registration new") return null;
            if (!mock.Engine.Zapret.Running) return BlockedWarpRegistration();
            registered = true;
            return new RunResult();
        };
        try
        {
            await mock.Engine.UseStrategyAsync(strategy);
            Check(registered && mock.Engine.State == EngineState.Connected && mock.Engine.Zapret.Running, "Normal connection resumes after protected registration");
            string config = File.ReadAllText(Path.Combine(mock.Engine.Zapret.Dir, "zarp.cfg"));
            Check(!config.Contains("--hostlist-domains=") && config.Contains("162.159.192.0"), "The API filter is replaced with the normal tunnel filter before connecting");
        }
        finally { await mock.Engine.DisconnectAsync(); mock.Engine.Zapret.Stop(); }
    }
}
