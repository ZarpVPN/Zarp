using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Zarp.Core;

static partial class Program
{
    const string WarpIpcTimeout = "Error communicating with daemon: The IPC call hit a timeout and could not be processed";

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", EntryPoint = "GetBestInterface")]
    static extern uint ReferenceIpv4Route(uint destination, out uint interfaceIndex);

    static MockWarp RegistrationMock()
    {
        var mock = new MockWarp();
        SetPrivate(mock.Engine.Warp, "RegistrationRetryDelayMs", 0);
        return mock;
    }

    static async Task TestWarpRegistrationRecoveryAsync()
    {
        var mock = RegistrationMock();
        int shows = 0;
        mock.Override = cmd => cmd == "registration show" ? (++shows == 1
            ? new RunResult { ExitCode = 1, Output = WarpIpcTimeout }
            : new RunResult { Output = WarpPlusRegistration }) : null;
        Check(await mock.Engine.Warp.EnsureRegisteredAsync(), "A temporary IPC timeout is followed by another read of the existing registration");
        Check(mock.Calls.SequenceEqual(new[] { "registration show", "registration show" }), "An IPC timeout must never create or delete a registration");
        Check(await mock.Engine.ApplyWarpLicenseAsync(WarpPlusTestKey) == WarpAccountType.Unlimited, "The retained registration can still use WARP+");

        foreach (string reply in new[] { WarpIpcTimeout, "Error: Old registration is still around. Try running: warp-cli registration delete", "OK" })
        {
            mock = RegistrationMock();
            shows = 0;
            mock.Override = cmd =>
            {
                if (cmd == "registration show") return ++shows <= 2
                    ? new RunResult { ExitCode = 1, Output = "Error: MissingRegistration" }
                    : new RunResult { Output = WarpPlusRegistration };
                if (cmd == "registration new") return new RunResult { ExitCode = reply == "OK" ? 0 : 1, Output = reply };
                return null;
            };
            Check(await mock.Engine.Warp.EnsureRegisteredAsync(), "A late registration is recovered after success, IPC timeout or an old-registration reply");
            Check(mock.Calls.Count(cmd => cmd == "registration new") == 1 && !mock.Calls.Any(cmd => cmd.Contains("delete")),
                  "Creation is attempted once and late completion never deletes an account");
            Check(mock.Engine.Warp.LastRegistrationError == null, "Recovery does not leave an error behind");
        }

        mock = RegistrationMock();
        shows = 0;
        mock.Override = cmd => cmd == "registration show" ? (++shows == 1
            ? new RunResult { ExitCode = 1, TimedOut = true, Output = "" }
            : new RunResult { Output = WarpPlusRegistration }) : null;
        Check(await mock.Engine.Warp.EnsureRegisteredAsync() && !mock.Calls.Contains("registration new"), "A process deadline is also not proof of a missing registration");

        foreach (string missing in new[] { "Missing Registration", "Registration Missing", "RegistrationNotFound", "No device registration found" })
        {
            mock = RegistrationMock();
            shows = 0;
            mock.Override = cmd => cmd == "registration show" ? (++shows == 1
                ? new RunResult { ExitCode = 1, Output = "Error: " + missing }
                : new RunResult { Output = WarpPlusRegistration }) : null;
            Check(await mock.Engine.Warp.EnsureRegisteredAsync() && mock.Calls.Count(cmd => cmd == "registration new") == 1,
                  "Recognized missing-registration replies allow one creation: " + missing);
        }
    }

    static async Task TestWarpRegistrationFailuresAsync()
    {
        var log = new List<string>();
        Action<string> capture = line => log.Add(line);
        Log.Line += capture;
        try
        {
            var mock = RegistrationMock();
            mock.Override = cmd => new RunResult { ExitCode = 1, Output = WarpIpcTimeout + "\n" + WarpPlusRegistration };
            Check(!await mock.Engine.Warp.EnsureRegisteredAsync(), "An unresponsive service fails after bounded retries");
            Check(mock.Calls.Count == 3 && mock.Calls.All(cmd => cmd == "registration show"), "Only read commands are retried while the daemon is unavailable");
            Check(mock.Engine.Warp.LastRegistrationError?.Key == "err.warpDaemon" && !log.Any(line => line.Contains(L.T("log.warpRegistering"))),
                  "A service timeout does not claim that WARP is unregistered");
            Check(log.All(line => !line.Contains(WarpPlusTestKey) && !line.Contains("private-device-id")), "Registration diagnostics hide account details");

            mock = RegistrationMock();
            mock.Override = cmd => new RunResult { ExitCode = 1, Output = "Unexpected error\n" + WarpPlusRegistration };
            Check(!await mock.Engine.Warp.EnsureRegisteredAsync() && mock.Calls.SequenceEqual(new[] { "registration show" }),
                  "An unknown read failure is not treated as a missing registration");
            Check(mock.Engine.Warp.LastRegistrationError?.Key == "err.warpRegistrationCheck", "An unknown read failure has a safe diagnostic");

            mock = RegistrationMock();
            mock.Override = cmd => new RunResult { ExitCode = 1, Output = cmd == "registration new"
                ? "Error: Old registration is still around. Try running: warp-cli registration delete" : "Error: MissingRegistration" };
            Check(!await mock.Engine.Warp.EnsureRegisteredAsync() && mock.Engine.Warp.LastRegistrationError?.Key == "err.warpRegistrationPending",
                  "A registration still being created is reported without deleting it");
            Check(!await mock.Engine.Warp.EnsureRegisteredAsync() && mock.Calls.Count(cmd => cmd == "registration new") == 1,
                  "Pressing Connect again during the pending period does not submit another creation");
            Check(!mock.Calls.Any(cmd => cmd.Contains("delete")), "Old registration errors never cause automatic deletion");

            mock = RegistrationMock();
            using (var cancel = new CancellationTokenSource())
            {
                mock.Override = cmd => { cancel.Cancel(); return new RunResult { ExitCode = 1, Output = WarpIpcTimeout }; };
                bool cancelled = false;
                try { await mock.Engine.Warp.EnsureRegisteredAsync(cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
                Check(cancelled && mock.Calls.Count == 1 && !mock.Calls.Contains("registration new"), "Cancellation interrupts waiting without creating a registration");
            }
        }
        finally { Log.Line -= capture; }
    }

    static void TestVpnRouteDetection()
    {
        var method = typeof(NetCheck).GetMethod("CarriesWarpTraffic", PrivateStatic);
        bool Carries(int v4, int v6, Func<IPAddress, int?> lookup) => (bool)method.Invoke(null, new object[] { v4, v6, lookup });
        Check(!Carries(40, 41, ip => 12), "A LAN overlay such as Radmin is ignored when the route to WARP uses the physical adapter");
        Check(Carries(40, 41, ip => ip.AddressFamily == AddressFamily.InterNetwork ? 40 : (int?)null), "A VPN carrying IPv4 WARP traffic is detected");
        Check(Carries(40, 41, ip => ip.AddressFamily == AddressFamily.InterNetworkV6 ? 41 : 12), "A VPN carrying IPv6 WARP traffic is detected");
        Check(!Carries(40, 41, ip => ip.AddressFamily == AddressFamily.InterNetworkV6 ? 40 : 41), "IPv4 and IPv6 interface indexes are compared in their own address family");
        Check(Carries(40, 41, ip => null), "An unreadable routing table preserves the conservative warning");
        Check(Carries(40, 41, ip => 0), "An invalid interface index is treated as an unknown route");
        var native = typeof(NetCheck).GetMethod("BestInterface", PrivateStatic);
        var known = new HashSet<int>();
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties();
                if (ni.Supports(System.Net.NetworkInformation.NetworkInterfaceComponent.IPv4)) known.Add(p.GetIPv4Properties().Index);
                if (ni.Supports(System.Net.NetworkInformation.NetworkInterfaceComponent.IPv6)) known.Add(p.GetIPv6Properties().Index);
            }
            catch (System.Net.NetworkInformation.NetworkInformationException) { }
        }
        foreach (string destination in new[] { "162.159.198.1", "2606:4700:102::1" })
        {
            var index = (int?)native.Invoke(null, new object[] { IPAddress.Parse(destination) });
            Check(!index.HasValue || known.Contains(index.Value), "The Windows route lookup returns a real interface or no route");
        }
        var ipv4 = IPAddress.Parse("162.159.198.1");
        uint status = ReferenceIpv4Route(BitConverter.ToUInt32(ipv4.GetAddressBytes(), 0), out var expected);
        int? actual = (int?)native.Invoke(null, new object[] { ipv4 });
        Check(status == 0 ? actual == (int)expected : !actual.HasValue, "The SOCKADDR-based lookup agrees with the independent IPv4 route API");
    }

    static void TestPersianTextDirection()
    {
        try
        {
            L.Apply("fa");
            Check(L.IsRightToLeft && L.Languages.Single(l => l.Code == "fa").NativeName == "فارسی", "Persian is offered under its native name and uses RTL text");
            using (var main = NewMain(NewEngine()))
            {
                Check(main.RightToLeft == RightToLeft.Yes, "The main window inherits Persian text direction");
                Check(GetPrivate<TextBox>(main, "_log").RightToLeft == RightToLeft.No, "Technical logs keep timestamp-first LTR direction");
                L.Apply("en");
                Application.DoEvents();
                Check(main.RightToLeft == RightToLeft.No && !L.IsRightToLeft, "Switching language restores LTR direction without restarting");
                L.Apply("fa");
                Application.DoEvents();
                Check(main.RightToLeft == RightToLeft.Yes, "Switching back to Persian restores RTL direction");
            }
            var engine = NewEngine();
            using (var connection = NewForm("ConnectionForm", engine))
            {
                Check(connection.RightToLeft == RightToLeft.Yes, "Connection dialogs support RTL text");
                foreach (string field in new[] { "_link", "_dns", "_endpoints" })
                    Check(GetPrivate<Control>(connection, field).Controls.OfType<TextBox>().Single().RightToLeft == RightToLeft.No,
                          "Links, DNS and endpoints remain LTR when Persian is selected");
            }
            using (var warp = NewForm("WarpPlusForm", engine))
                Check(GetPrivate<Control>(warp, "_key").Controls.OfType<TextBox>().Single().RightToLeft == RightToLeft.No, "License keys remain LTR");
            using (var apps = NewForm("AppsForm", engine))
                Check(GetPrivate<Control>(apps, "_search").Controls.OfType<TextBox>().Single().RightToLeft == RightToLeft.Yes, "Human-language search accepts Persian in RTL direction");
        }
        finally { L.Apply("en"); }
    }
}
