using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Zarp.Core;

// Ручной тест с НАСТОЯЩИМ виртуальным адаптером Zarp, настоящим winws2 (WinDivert) и настоящим сервером. Обычный прогон его пропускает:
// он запускается только при заданной переменной ZARP_REAL_ADAPTER_LINK, от имени администратора и когда нет ни одного стороннего VPN
// и другого winws/GoodbyeDPI (чужое тест не трогает и не выключает). Проверяет то, чего не видит ни один тест на localhost: что
// соединение Xray (и sing-box) с сервером идёт мимо адаптера Zarp, а не возвращается в него, и что winws2 работает со стратегией
// найденной пары. Подробности и команды запуска: docs/testing.md.
static partial class Program
{
    const string RealAdapterVariable = "ZARP_REAL_ADAPTER_LINK";

    sealed class TcpRow
    {
        public IPAddress Local, Remote;
        public int LocalPort, RemotePort, State, Pid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

    /// <summary>Таблица TCP-соединений системы с процессом-владельцем (IPv4 и IPv6).</summary>
    static List<TcpRow> TcpRows()
    {
        const int AfInet = 2, AfInet6 = 23, OwnerPidAll = 5, InsufficientBuffer = 122;
        var rows = new List<TcpRow>();
        foreach (int family in new[] { AfInet, AfInet6 })
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, OwnerPidAll, 0);
            for (int attempt = 0; attempt < 5; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint result = GetExtendedTcpTable(buffer, ref size, false, family, OwnerPidAll, 0);
                    if (result == InsufficientBuffer) continue; // таблица выросла между вызовами
                    if (result != 0) break;
                    int count = Marshal.ReadInt32(buffer);
                    int rowSize = family == AfInet ? 24 : 56;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr row = buffer + 4 + i * rowSize;
                        if (family == AfInet)
                            rows.Add(new TcpRow
                            {
                                State = Marshal.ReadInt32(row, 0),
                                Local = new IPAddress((uint)Marshal.ReadInt32(row, 4)), LocalPort = NetworkPort(Marshal.ReadInt32(row, 8)),
                                Remote = new IPAddress((uint)Marshal.ReadInt32(row, 12)), RemotePort = NetworkPort(Marshal.ReadInt32(row, 16)),
                                Pid = Marshal.ReadInt32(row, 20),
                            });
                        else
                        {
                            var local = new byte[16];
                            var remote = new byte[16];
                            Marshal.Copy(row, local, 0, 16);
                            Marshal.Copy(row + 24, remote, 0, 16);
                            rows.Add(new TcpRow
                            {
                                Local = new IPAddress(local), LocalPort = NetworkPort(Marshal.ReadInt32(row, 20)),
                                Remote = new IPAddress(remote), RemotePort = NetworkPort(Marshal.ReadInt32(row, 44)),
                                State = Marshal.ReadInt32(row, 48), Pid = Marshal.ReadInt32(row, 52),
                            });
                        }
                    }
                    break;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        return rows;
    }

    // порт в таблице лежит в сетевом порядке байт в младших 16 разрядах
    static int NetworkPort(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    /// <summary>Имя сетевого адаптера, у которого есть такой адрес, или null.</summary>
    static string InterfaceOf(IPAddress address)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (ni.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(address))) return ni.Name;
            }
            catch (NetworkInformationException) { }
        }
        return null;
    }

    /// <summary>Таблица TCP, на которой строится ручной тест, читается верно: свои соединения на localhost, IPv4 и IPv6, прослушивание и порты.</summary>
    static void TestTcpTable()
    {
        int pid = Process.GetCurrentProcess().Id;
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !System.Net.Sockets.Socket.OSSupportsIPv6) continue;
            var listener = new System.Net.Sockets.TcpListener(address, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Check(TcpRows().Count(r => r.Pid == pid && r.State == 2 && r.LocalPort == port && r.Local.Equals(address)) == 1, address + ": the listening socket must be found by address, port and owner");
                using (var client = new System.Net.Sockets.TcpClient(address.AddressFamily))
                {
                    try { client.Connect(address, port); }
                    catch (System.Net.Sockets.SocketException e) when (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        // на некоторых компьютерах (фильтры другого VPN или брандмауэра) соединения по ::1 запрещены: это не ошибка программы
                        Console.WriteLine("IPv6 loopback connections are refused on this computer (" + e.SocketErrorCode + "): only the listening row was checked.");
                        continue;
                    }
                    using (var accepted = listener.AcceptTcpClient())
                    {
                        int clientPort = ((IPEndPoint)client.Client.LocalEndPoint).Port;
                        var rows = TcpRows().Where(r => r.Pid == pid).ToList();
                        var listening = rows.Where(r => r.State == 2 && r.LocalPort == port && r.Local.Equals(address)).ToList();
                        var outgoing = rows.Where(r => r.State == 5 && r.LocalPort == clientPort && r.RemotePort == port).ToList();
                        var incoming = rows.Where(r => r.State == 5 && r.LocalPort == port && r.RemotePort == clientPort).ToList();
                        Check(listening.Count == 1, address + ": the listening socket must be found by address and port");
                        Check(outgoing.Count == 1 && outgoing[0].Local.Equals(address) && outgoing[0].Remote.Equals(address), address + ": the outgoing connection must be found with both addresses");
                        Check(incoming.Count == 1 && incoming[0].Local.Equals(address) && incoming[0].Remote.Equals(address), address + ": the accepted end of the connection must be found too");
                        Check(InterfaceOf(address) != null && InterfaceOf(address) != SingBox.TunName, address + ": the loopback address belongs to a known interface other than Zarp");
                    }
                }
            }
            finally { listener.Stop(); }
        }
        Check(InterfaceOf(IPAddress.Parse("203.0.113.77")) == null, "An address that nothing has belongs to no interface");
        Check(NetworkPort(0x5000) == 0x0050 && NetworkPort(0xBB01) == 443 && NetworkPort(0x0100) == 1, "Ports are read from the network byte order");
    }

    static bool AdapterExists(string name, bool mustBeUp = false) =>
        NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == name && (!mustBeUp || n.OperationalStatus == OperationalStatus.Up));

    static List<int> ProcessIds(string processName, string exe)
    {
        var ids = new List<int>();
        foreach (var p in Process.GetProcessesByName(processName))
            using (p)
            {
                string path = ProcessUtil.GetProcessPath(p);
                if (path != null && ProcessUtil.SamePath(path, exe)) ids.Add(p.Id);
            }
        return ids;
    }

    /// <summary>Адрес, с которого интернет видит этот компьютер (ip= в cdn-cgi/trace), по маршруту системы, без прокси.</summary>
    static async Task<string> PublicAddressAsync()
    {
        using (var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(20) })
        {
            try
            {
                string text = await http.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace?" + Guid.NewGuid().ToString("N")).ConfigureAwait(false);
                var match = Regex.Match(text, @"^ip=(.+)$", RegexOptions.Multiline);
                return match.Success ? match.Groups[1].Value.Trim() : null;
            }
            catch (Exception) { return null; }
        }
    }

    static async Task<bool> UntilAsync(Func<bool> condition, int seconds)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed.TotalSeconds < seconds)
        {
            if (condition()) return true;
            await Task.Delay(300).ConfigureAwait(false);
        }
        return condition();
    }

    /// <summary>
    /// Отказ ручного теста. Причина печатается сразу: при запуске с --run-test (см. docs/testing.md) раннер ничего о пропуске не пишет,
    /// а пользователю нужно увидеть, что сделать (выключить VPN, запустить от администратора).
    /// </summary>
    static TestSkippedException ManualSkip(string reason)
    {
        Console.WriteLine("[manual] SKIPPED: " + reason);
        return new TestSkippedException(reason);
    }

    /// <summary>
    /// Ручной тест: настоящее подключение через ваш сервер с настоящим адаптером. Ничего не делает без ZARP_REAL_ADAPTER_LINK.
    /// Ссылка и адрес сервера в вывод не попадают.
    /// </summary>
    static async Task TestRealAdapterAsync()
    {
        string link = Environment.GetEnvironmentVariable(RealAdapterVariable);
        if (string.IsNullOrWhiteSpace(link))
            throw ManualSkip("Manual test, not part of a normal run: it creates the real Zarp adapter. To run it, turn every VPN off, start an administrator PowerShell, " +
                                           "set $env:" + RealAdapterVariable + " to the link of your server and run: Zarp.Tests.exe --run-test TestRealAdapterAsync --artifacts build/real (see docs/testing.md).");
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw ManualSkip("Start the test from an administrator PowerShell: the adapter needs administrator rights.");
        link = link.Trim();
        var why = ProxySource.Explain(link);
        Check(why == null, "The link in " + RealAdapterVariable + " cannot be used: " + why);
        bool subscription = Subscription.IsUrl(link); // адрес подписки: серверы загружаются, подключается лучший
        var single = subscription ? null : ProxyProfile.Parse(link);
        var vpns = NetCheck.ForeignVpnAdapters();
        if (vpns.Count > 0)
            throw ManualSkip("Another VPN is on: " + string.Join("; ", vpns) + ". The test never touches it: turn it off yourself and run the test again.");
        if (AdapterExists(SingBox.TunName))
            throw ManualSkip("An adapter named " + SingBox.TunName + " already exists (is the Zarp app connected?). Disconnect it first.");
        // чужой winws/winws2/GoodbyeDPI мешал бы перехвату и портил бы проверки: тест его не трогает, а отказывается работать
        var foreignDpi = new Zapret(Path.Combine(_data, "foreign-dpi-check")).ForeignDpiTools().ToList();
        if (foreignDpi.Count > 0)
            throw ManualSkip("Another winws/winws2/GoodbyeDPI is running: " + string.Join("; ", foreignDpi) + ". The test never touches it: stop it yourself and run the test again.");

        var singBoxVersion = typeof(SingBox).GetField("_embeddedVersion", PrivateStatic);
        var xrayVersion = typeof(Xray).GetField("_embeddedVersion", PrivateStatic);
        var zapretVersion = typeof(Zapret).GetField("_embeddedVersion", PrivateStatic);
        singBoxVersion.SetValue(null, null); // остальные проверки идут с выключенными вшитыми программами
        xrayVersion.SetValue(null, null);
        zapretVersion.SetValue(null, null);
        try
        {
            if (SingBox.EmbeddedVersion == null)
                throw ManualSkip("Zarp was built without embedded sing-box; run tools/fetch-singbox.ps1 before building.");
            if (Zapret.EmbeddedVersion == null)
                throw ManualSkip("Zarp was built without embedded zapret2; run tools/fetch-zapret.ps1 before building.");
            // в подписке заранее неизвестно, есть ли XHTTP: Xray нужен на случай, если он там есть
            if ((subscription || single.UsesXray) && Xray.EmbeddedVersion == null)
                throw ManualSkip("Zarp was built without embedded Xray; run tools/fetch-xray.ps1 before building.");
            await RunRealAdapterAsync(link, single).ConfigureAwait(false);
        }
        finally
        {
            singBoxVersion.SetValue(null, "");
            xrayVersion.SetValue(null, "");
            zapretVersion.SetValue(null, "");
        }
    }

    /// <summary>single - сервер из ссылки; null - link это адрес подписки, и подключится тот из её серверов, который окажется лучшим.</summary>
    static async Task RunRealAdapterAsync(string link, ProxyProfile single)
    {
        string directAddress = await PublicAddressAsync().ConfigureAwait(false);
        Check(directAddress != null, "Setup: the internet must work without the tunnel (and without any VPN) before the test starts");

        var engine = NewEngine();
        engine.Config.UseProxy = true;
        engine.Config.ProxyUri = link;
        engine.Config.StopAfterWorking = 1; // первая же проверенная пара: ручному тесту нужно подключение, а не полный разбор
        if (single == null)
        {
            // подписка загружается до адаптера, пока сеть обычная; серверы в вывод не попадают
            var loaded = await engine.LoadSubscriptionAsync(link).ConfigureAwait(false);
            Check(loaded.Servers.Count > 0, "The subscription must give at least one server Zarp can use (unsupported links: " + loaded.Unsupported + ", unreadable: " + loaded.Refused + ")");
        }
        engine.ReloadStrategies();
        // серверы (а не пары): у каждого сервера свои стратегии zapret2, пар в списке много
        var profiles = engine.Candidates.Select(c => c.Profile).GroupBy(p => p.Id).Select(g => g.First()).ToList();
        Check(profiles.Count > 0, "There must be a server to connect to");
        int pairCount = engine.Candidates.Count;
        // адреса серверов до подключения: после него системный DNS идёт через туннель
        var serverAddresses = new List<IPAddress>();
        foreach (var host in profiles.Select(p => p.Host).Distinct())
        {
            try { serverAddresses.AddRange(IPAddress.TryParse(host, out var literal) ? new[] { literal } : Dns.GetHostAddresses(host)); }
            catch (Exception) { } // сервер, имя которого не разрешается, всё равно будет проверен и отброшен программой
        }
        string Redact(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            foreach (var host in profiles.Select(p => p.Host).Distinct().OrderByDescending(h => h.Length)) text = text.Replace(host, "<server>");
            foreach (var address in serverAddresses) text = text.Replace(address.ToString(), "<server>");
            return text.Replace(link, "<link>");
        }
        void Say(string text) => Console.WriteLine("[manual] " + Redact(text));
        Say("direct address read; " + profiles.Count + " server(s) and " + pairCount + " pairs of a zapret2 strategy and a server to search; the test starts the real winws2 and creates the real adapter '" + SingBox.TunName + "' now and removes both at the end");

        var runtime = GetPrivate<ProxyRuntime>(engine, "Proxy");
        var lines = new StringBuilder();
        Action<string> collect = line => { lock (lines) lines.AppendLine(Redact(line)); };
        Log.Line += collect;
        string Tail() { lock (lines) return string.Join(Environment.NewLine, lines.ToString().Split('\n').Reverse().Take(25).Reverse()); }

        // что бы ни случилось, до конца срока теста сеть возвращается: раннер убил бы процесс, а sing-box после этого продолжил бы работать.
        // Срок большой: поиск по парам «стратегия + сервер» идёт, пока не найдётся рабочая, и каждая неработающая ждёт свой срок проверки
        using (var watchdog = new CancellationTokenSource())
        {
            var guard = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(840), watchdog.Token).ConfigureAwait(false);
                    runtime.Stop();
                    engine.Zapret.Stop();
                    Say("time is up: the tunnel and winws2 were stopped");
                }
                catch (OperationCanceledException) { }
            });
            try
            {
                await engine.ConnectAsync().ConfigureAwait(false);
                Check(engine.State == EngineState.Connected, "Connecting through the server failed: " + engine.State + " / " + Redact(engine.Detail) + Environment.NewLine + Tail());
                // дальше проверяется тот сервер, с которым программа подключилась (в подписке - лучший из проверенных), и стратегия его пары
                Check(engine.Selected != null, "The engine must say which pair it connected with");
                var profile = engine.Selected.Profile;
                Say("connected with the pair '" + engine.Selected.Name + "'" + (profile.UsesXray ? " (sing-box and the Xray bridge)" : " (sing-box)"));
                Check(AdapterExists(SingBox.TunName, mustBeUp: true), "The " + SingBox.TunName + " adapter must be up");

                // zapret2 обязателен: winws2 работает со стратегией пары и перехватывает соединение именно с этим сервером
                Check(engine.Zapret.Running && engine.Zapret.RunningStrategyArgs() == engine.Selected.Args.Trim(), "winws2 must be running with the strategy of the chosen pair" + Environment.NewLine + Tail());
                string winwsConfig = File.ReadAllText(Path.Combine(engine.Zapret.Dir, "zarp.cfg"));
                var chosenAddresses = GetPrivate<Dictionary<string, string>>(engine, "_proxyAddresses");
                Check(chosenAddresses.TryGetValue(profile.Host, out var interceptedAddress) && winwsConfig.Contains("DstAddr==" + interceptedAddress) &&
                      winwsConfig.Contains((engine.Selected.Transport == WarpTransport.MasqueH3 ? "udp.DstPort==" : "--wf-tcp-out=") + profile.Port),
                    "winws2 must intercept the connection to the address and the port of the server only");
                Say("winws2 runs with the strategy of the pair and intercepts the connection to the server");

                // трафик идёт сквозь туннель
                string tunnelAddress = await PublicAddressAsync().ConfigureAwait(false);
                Check(tunnelAddress != null, "A request of this program through the tunnel must work" + Environment.NewLine + Tail());
                Say("exit address " + (tunnelAddress != directAddress
                    ? "differs from the direct one: the traffic leaves through the server"
                    : "is the same as the direct one (a server on your own address?), so the routing check below is the one that matters"));

                // соединение программ с сервером идёт мимо адаптера Zarp, а не возвращается в него (петля)
                var programs = new[]
                {
                    (Name: "sing-box", Ids: ProcessIds("sing-box", engine.SingBox.Exe)),
                    (Name: "Xray", Ids: ProcessIds("xray", engine.Xray.Exe)),
                };
                Check(programs[0].Ids.Count > 0 && (!profile.UsesXray || programs[1].Ids.Count > 0), "The programs of the tunnel must be running");
                bool maybeQuic = profile.UsesQuic;
                // адреса, которые программа выбрала сама (у имени бывает несколько адресов), тоже считаются адресами сервера
                foreach (var chosen in GetPrivate<Dictionary<string, string>>(engine, "_proxyAddresses").Values)
                    if (IPAddress.TryParse(chosen, out var picked)) serverAddresses.Add(picked);
                var seen = new HashSet<string>();
                var clock = Stopwatch.StartNew();
                while (clock.Elapsed.TotalSeconds < 20 && !(seen.Count > 0 && (!profile.UsesXray || seen.Contains("Xray"))))
                {
                    await PublicAddressAsync().ConfigureAwait(false); // живое соединение с сервером
                    foreach (var row in TcpRows().Where(r => r.State == 5 && r.RemotePort == profile.Port && serverAddresses.Any(a => a.Equals(r.Remote))))
                        foreach (var program in programs.Where(p => p.Ids.Contains(row.Pid)))
                        {
                            string nic = InterfaceOf(row.Local);
                            Check(nic != null && nic != SingBox.TunName, program.Name + " reaches the server THROUGH the " + SingBox.TunName + " adapter (a routing loop), local interface: " + (nic ?? "unknown"));
                            if (seen.Add(program.Name)) Say(program.Name + " connects to the server through the interface '" + nic + "', not through " + SingBox.TunName);
                        }
                }
                if (seen.Count == 0 && !maybeQuic)
                    Check(false, "No TCP connection of sing-box or Xray to the server was visible, so the routing loop check could not be made");
                if (seen.Count == 0) Say("WARNING: the link may use QUIC (UDP), which this check cannot see; the loop check was NOT made");
                else if (profile.UsesXray && !seen.Contains("Xray") && !maybeQuic) Check(false, "The connection of Xray to the server was not visible, so the routing loop check could not be made for it");

                // DNS через туннель
                var resolved = await Task.WhenAny(Task.Run(() => Dns.GetHostAddresses("one.one.one.one")), Task.Delay(20000)).ConfigureAwait(false);
                Check(resolved is Task<IPAddress[]> done && done.IsCompleted && done.Result.Length > 0, "A name must resolve through the tunnel");
                Say("DNS works through the tunnel");

                // устойчивость: несколько проверок подряд, фоновая проверка движка
                for (int i = 0; i < 4; i++)
                {
                    await Task.Delay(5000).ConfigureAwait(false);
                    string again = await PublicAddressAsync().ConfigureAwait(false);
                    Check(again != null, "Round " + (i + 1) + " of 4: the connection through the tunnel must stay up" + Environment.NewLine + Tail());
                    if (again != tunnelAddress) Say("the exit address changed during the test (a server with several exit addresses?)");
                    await engine.MonitorAsync().ConfigureAwait(false);
                    Check(engine.State == EngineState.Connected, "Round " + (i + 1) + " of 4: the engine must still see a working tunnel: " + engine.State + " / " + Redact(engine.Detail));
                }
                Say("the tunnel stayed up for 20 seconds");

                // отключение возвращает сеть
                await engine.DisconnectAsync().ConfigureAwait(false);
                Check(await UntilAsync(() => !AdapterExists(SingBox.TunName), 15).ConfigureAwait(false), "The " + SingBox.TunName + " adapter must be gone after disconnecting");
                Check(ProcessIds("sing-box", engine.SingBox.Exe).Count == 0 && ProcessIds("xray", engine.Xray.Exe).Count == 0 && ProcessIds("winws2", engine.Zapret.Exe).Count == 0 && !engine.Zapret.Running,
                    "No program of the tunnel, winws2 included, may be left running");
                string after = null;
                await UntilAsync(() => (after = PublicAddressAsync().GetAwaiter().GetResult()) != null, 30).ConfigureAwait(false);
                Check(after != null, "The internet must work without the tunnel again");
                Say("disconnected: the adapter and the programs are gone, the direct address is " + (after == directAddress ? "back" : "reachable (it changed meanwhile)"));
                Say("PASSED: nothing loops, the tunnel carries traffic and disconnecting leaves nothing behind");
            }
            finally
            {
                watchdog.Cancel();
                try { await guard.ConfigureAwait(false); } catch { }
                runtime.Stop();
                engine.Zapret.Stop();
                Log.Line -= collect;
                // в настройках лежит ссылка с секретами, а в сохранённой подписке - ссылки всех её серверов: после теста их не остаётся даже у упавшего случая
                try { File.Delete(Path.Combine(engine.DataDir, "zarp.json")); } catch { }
                try { File.Delete(Path.Combine(engine.DataDir, "subscription.json")); } catch { }
            }
        }
    }
}
