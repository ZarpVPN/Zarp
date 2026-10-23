using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Zarp.Core;

static partial class Program
{
    const string WarpPlusTestKey = "AbCd1234-EfGh5678-IjKl9012";
    const string WarpPlusRegistration = "Account type: Unlimited\r\nLicense: " + WarpPlusTestKey + "\r\nDevice ID: private-device-id\r\n";

    static async Task TestWarpPlusAccountAsync()
    {
        Check(Warp.IsLicenseValid(WarpPlusTestKey) && Warp.IsLicenseValid("  " + WarpPlusTestKey + "\r\n"), "Copied WARP keys accept surrounding whitespace");
        var mock = new MockWarp(PlainStrategy("warp-plus"));
        var warp = mock.Engine.Warp;
        foreach (string bad in new[] { null, "", "--help", WarpPlusTestKey + " connect", WarpPlusTestKey + "\r\nconnect", "абвг1234-EfGh5678-IjKl9012", "AbCd123-EfGh5678-IjKl9012" })
        {
            Check(!Warp.IsLicenseValid(bad), "Malformed keys and extra arguments are refused");
            Check(Catch(() => warp.ApplyLicenseAsync(bad).GetAwaiter().GetResult()) is ArgumentException, "An invalid key fails before any CLI command");
        }
        Check(mock.Calls.Count == 0, "No command ran for invalid input");

        var parse = typeof(Warp).GetMethod("ParseAccountType", PrivateStatic);
        foreach (var item in new[] { ("Free", WarpAccountType.Free), ("Limited", WarpAccountType.Plus), ("Unlimited", WarpAccountType.Unlimited),
                                    ("Team", WarpAccountType.ZeroTrust), ("future type " + WarpPlusTestKey, WarpAccountType.Unknown) })
            Check((WarpAccountType)parse.Invoke(null, new object[] { "Device: private-device-id\r\n  Account type: " + item.Item1 + "\r\nLicense: " + WarpPlusTestKey }) == item.Item2,
                  "Only known account types leave the parser");
        Check((WarpAccountType)parse.Invoke(null, new object[] { "Error: Account type: Unlimited" }) == WarpAccountType.Unknown, "An error quoting an account type is not a subscription");

        mock.Override = cmd => cmd == "registration show" ? new RunResult { Output = WarpPlusRegistration } : null;
        Check(await warp.ApplyLicenseAsync(" " + WarpPlusTestKey + " ") == WarpAccountType.Unlimited, "A license is applied and its account checked");
        Check(mock.Calls.SequenceEqual(new[] { "registration show", "registration license " + WarpPlusTestKey, "registration show" }),
              "Existing registrations are reused without reset, delete, new, transport or endpoint changes");

        mock.Calls.Clear();
        int reads = 0;
        mock.Override = cmd => cmd == "registration show" ? (++reads == 1 ? new RunResult { ExitCode = 1, Output = "Error: MissingRegistration" } : new RunResult { Output = WarpPlusRegistration }) : null;
        Check(await warp.ApplyLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unlimited &&
              mock.Calls.SequenceEqual(new[] { "registration show", "registration new", "registration show", "registration license " + WarpPlusTestKey, "registration show" }),
              "A new device is registered before linking its subscription");
    }

    static async Task TestWarpPlusFailuresAsync()
    {
        var mock = new MockWarp();
        var log = new List<string>();
        Action<string> capture = line => log.Add(line);
        Log.Line += capture;
        try
        {
            foreach (int failure in new[] { 0, 1, 2, 3 })
            {
                mock.Calls.Clear();
                mock.Override = cmd =>
                {
                    if (failure == 3) return new RunResult { ExitCode = 1, Output = WarpPlusRegistration };
                    if (cmd.StartsWith("registration license ", StringComparison.Ordinal))
                    {
                        if (failure == 2) throw new IOException(WarpPlusRegistration);
                        return new RunResult { ExitCode = 1, TimedOut = failure == 1, Output = WarpPlusRegistration };
                    }
                    return new RunResult { Output = WarpPlusRegistration };
                };
                var error = Catch(() => mock.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey).GetAwaiter().GetResult());
                Check(error is IOException && !error.ToString().Contains(WarpPlusTestKey) && !error.ToString().Contains("private-device-id"),
                      "CLI errors, exceptions, registration failures and deadlines never expose account data");
                Check(error.Message == L.T(failure == 1 ? "warpPlus.timeout" : "warpPlus.applyFailed"), "A deadline explains that the key may already be applied");
                Check(!mock.Engine.IsBusy && mock.Engine.State == EngineState.Idle, "An account error releases the engine without altering the connection state");
            }
            mock.Override = cmd => cmd == "registration show" ? new RunResult { ExitCode = 1, Output = WarpPlusRegistration } : null;
            Check(await mock.Engine.Warp.ReadAccountAsync() == WarpAccountType.Unknown, "Failed account reads cannot confirm WARP+");
            int reads = 0;
            mock.Override = cmd => cmd == "registration show" ? new RunResult { ExitCode = ++reads == 2 ? 1 : 0, Output = WarpPlusRegistration } : null;
            Check(await mock.Engine.Warp.ApplyLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unknown, "A successful apply with failed verification is unconfirmed");
            Check(log.All(line => !line.Contains(WarpPlusTestKey) && !line.Contains("private-device-id")), "No account data appears in the Zarp log");
        }
        finally { Log.Line -= capture; }
    }

    static async Task TestWarpPlusEngineAsync()
    {
        var strategy = Tagged("warp-plus-zapret", SplitArgs, "ru");
        var mock = new MockWarp(strategy);
        var engine = mock.Engine;
        UseSleepingWinws(engine, Path.Combine(_data, "warp-plus-winws"));
        mock.Override = cmd => cmd == "registration show" ? new RunResult { Output = WarpPlusRegistration } : null;
        engine.Config.CustomEndpoints = "162.159.198.2:443";
        try
        {
            Check(await engine.ApplyWarpLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unlimited, "The engine can link WARP+");
            await engine.UseStrategyAsync(strategy);
            Check(engine.State == EngineState.Connected && engine.Zapret.Running, "WARP+ uses the normal connection with zapret2 running");
            Check(mock.Calls.Contains("tunnel endpoint set 162.159.198.2:443"), "WARP+ retains the configured endpoint");
            string before = File.ReadAllText(Path.Combine(engine.DataDir, "zarp.json"));
            mock.Calls.Clear();
            Check(await engine.ApplyWarpLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unlimited, "A subscription can be linked while the tunnel is up");
            Check(engine.State == EngineState.Connected && engine.Zapret.Running && engine.Config.SelectedStrategyId == strategy.Id &&
                  !mock.Calls.Contains("disconnect") && !mock.Calls.Contains("registration new"), "License changes preserve the connected strategy, tunnel and zapret2");
            Check(File.ReadAllText(Path.Combine(engine.DataDir, "zarp.json")) == before && !before.Contains(WarpPlusTestKey), "Zarp saves no license and does not invalidate strategy results");

            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            SetPrivate(engine.Warp, "CommandRunner", (Func<string, int, CancellationToken, Task<RunResult>>)(async (cmd, timeout, ct) =>
            {
                started.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, ct);
                return new RunResult();
            }));
            using (var cancel = new CancellationTokenSource())
            {
                var applying = engine.ApplyWarpLicenseAsync(WarpPlusTestKey, cancel.Token);
                await started.Task;
                Check(engine.IsBusy, "Account operations reserve the engine");
                Check(Catch(() => engine.ApplyWarpLicenseAsync(WarpPlusTestKey).GetAwaiter().GetResult()) is InvalidOperationException,
                      "A second license operation cannot run concurrently");
                Check(!engine.ApplyConnection("", true, "trojan://secret@example.test:443"), "The connection mode cannot change during a license operation");
                await engine.DisconnectAsync();
                Check(engine.Zapret.Running, "Another operation cannot stop the strategy while the account is changing");
                cancel.Cancel();
                bool cancelled = false;
                try { await applying; } catch (OperationCanceledException) { cancelled = true; }
                Check(cancelled, "Cancelling the account operation propagates cancellation");
            }
            Check(!engine.IsBusy && engine.State == EngineState.Connected && engine.Zapret.Running, "Cancelling a license operation leaves the existing tunnel running");
            SetPrivate(engine.Warp, "CommandRunner", (Func<string, int, CancellationToken, Task<RunResult>>)((cmd, timeout, ct) => Task.FromResult(
                new RunResult { Output = cmd.Contains("status") ? "{\"status\":\"Disconnected\"}" : "OK" })));
            await engine.DisconnectAsync();
            Check(!engine.Zapret.Running, "Normal disconnection still stops zapret2");
        }
        finally { engine.Zapret.Stop(); }

        var observing = new MockWarp { Status = "Connected" };
        var measuring = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        SetPrivate(observing.Engine, "MeasureTraffic", (Func<int, CancellationToken, Task<int>>)(async (samples, ct) =>
        {
            measuring.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, ct);
            return 20;
        }));
        observing.Override = cmd => cmd == "registration show" ? new RunResult { Output = WarpPlusRegistration } : null;
        var observation = observing.Engine.MonitorAsync();
        await measuring.Task;
        using (var limit = new CancellationTokenSource(5000))
            Check(await observing.Engine.ReadWarpAccountAsync(limit.Token) == WarpAccountType.Unlimited, "Reading the account takes priority over a background traffic measurement");
        await observation;

        var stopping = new MockWarp();
        var reading = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        SetPrivate(stopping.Engine.Warp, "CommandRunner", (Func<string, int, CancellationToken, Task<RunResult>>)(async (cmd, timeout, ct) =>
        {
            reading.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, ct);
            return new RunResult();
        }));
        var pending = stopping.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey);
        await reading.Task;
        await stopping.Engine.ShutdownAsync();
        bool stopped = false;
        try { await pending; } catch (OperationCanceledException) { stopped = true; }
        Check(stopped && !stopping.Engine.IsBusy, "Shutdown cancels an account request and waits for it to release the engine");
    }

    static void TestWarpPlusForm()
    {
        var mock = new MockWarp();
        mock.Override = cmd => cmd == "registration show" ? new RunResult { Output = WarpPlusRegistration } : null;
        using (var form = NewForm("WarpPlusForm", mock.Engine))
        {
            PositionOffscreen(form);
            form.Show();
            Application.DoEvents();
            var key = GetPrivate<Control>(form, "_key");
            var apply = GetPrivate<Button>(form, "_apply");
            var refresh = GetPrivate<Button>(form, "_refresh");
            var account = GetPrivate<Label>(form, "_account");
            var status = GetPrivate<Label>(form, "_status");
            PumpUntil(() => refresh.Enabled);
            Check(!apply.Enabled && account.Text == L.T("warpPlus.account", L.T("warpPlus.unlimited")), "The window reads the account without showing its key or device ID");
            Check(key.Controls.OfType<TextBox>().Single().UseSystemPasswordChar, "The license field is masked");
            key.Text = "not-a-license";
            Check(!apply.Enabled && status.Text == L.T("warpPlus.invalid"), "Malformed license keys cannot be applied");
            key.Text = WarpPlusTestKey;
            apply.PerformClick();
            PumpUntil(() => refresh.Enabled);
            Check(key.Text == "" && !apply.Enabled && status.Text == L.T("warpPlus.applied"), "A verified license clears the field and asks to reconnect through Zarp");

            mock.Override = cmd => cmd == "registration show" ? new RunResult { Output = "Account type: Free\nLicense: " + WarpPlusTestKey } : null;
            key.Text = WarpPlusTestKey;
            apply.PerformClick();
            PumpUntil(() => refresh.Enabled);
            Check(status.Text == L.T("warpPlus.unconfirmed"), "Accepting a key for a free account never claims WARP+ is active");

            mock.Override = cmd => cmd.StartsWith("registration license ", StringComparison.Ordinal) ? new RunResult { ExitCode = 1, Output = WarpPlusRegistration } : null;
            key.Text = WarpPlusTestKey;
            apply.PerformClick();
            PumpUntil(() => refresh.Enabled);
            Check(status.Text == L.T("warpPlus.applyFailed") && key.Text == WarpPlusTestKey && apply.Enabled, "Failure is private and the user can retry");
        }

        // Закрытие во время команды отменяет ожидание и освобождает движок, не отключая туннель.
        var stalled = new MockWarp();
        SetPrivate(stalled.Engine.Warp, "CommandRunner", (Func<string, int, CancellationToken, Task<RunResult>>)(async (cmd, timeout, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new RunResult();
        }));
        using (var form = NewForm("WarpPlusForm", stalled.Engine))
        {
            PositionOffscreen(form);
            form.Show();
            PumpUntil(() => stalled.Engine.IsBusy);
            Check(!GetPrivate<Button>(form, "_refresh").Enabled, "Buttons are disabled while WARP answers");
            form.Close();
            PumpUntil(() => !stalled.Engine.IsBusy);
        }
    }
}
