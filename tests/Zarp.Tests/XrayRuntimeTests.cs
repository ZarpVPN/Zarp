using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Zarp.Core;

// Мост Xray в работе: настоящие xray.exe и sing-box, только на localhost и без виртуального адаптера. Сервер XHTTP - тоже настоящий Xray.
static partial class Program
{
    static void WithEmbeddedEngines(Action<SingBox, Xray> test) => WithEmbeddedSingBox(box =>
    {
        var embedded = typeof(Xray).GetField("_embeddedVersion", PrivateStatic);
        embedded.SetValue(null, null); // остальные проверки идут с выключенным вшитым Xray
        try
        {
            if (Xray.EmbeddedVersion == null)
                throw new TestSkippedException("Zarp was built without embedded Xray; run tools/fetch-xray.ps1 before building.");
            var xray = new Xray(Path.Combine(_data, "xray-run"));
            Check(xray.ExtractEmbedded() && xray.Installed && xray.Version == Xray.EmbeddedVersion, "The embedded Xray must unpack");
            Console.WriteLine("Embedded Xray: " + Xray.EmbeddedVersion);
            test(box, xray);
        }
        finally { embedded.SetValue(null, ""); }
    });

    static RunResult XrayRun(Xray xray, string args) =>
        UntilLoaded("Xray", () => Sync(() => ProcessUtil.RunAsync(xray.Exe, args, 30000)), LoaderKilled);

    // запуск через cmd скрывает код выхода: убитый загрузчиком процесс ничего не пишет в журнал, а настоящая ошибка пишет; то же для проверки конфигурации без вывода
    static bool LoaderSilent(Msg err) => err != null && (err.Key == "err.singboxExitedSilent" || err.Key == "err.xrayExitedSilent" ||
        ((err.Key == "err.singboxConfig" || err.Key == "err.xrayConfig") && string.IsNullOrWhiteSpace(Convert.ToString(err.Args[0]))));

    static Msg StartRuntime(ProxyRuntime runtime, ProxySession session) =>
        UntilLoaded("sing-box or Xray", () => Sync(() => runtime.StartAsync(session, CancellationToken.None)), LoaderSilent);

    /// <summary>Мост Xray без sing-box. Запуск, убитый загрузчиком Windows, повторяется (как и остальные запуски в тестах).</summary>
    static Msg StartBridgeOnly(Xray xray, string config, int port) =>
        UntilLoaded("Xray", () => Sync(() => xray.StartAsync(config, port)), LoaderSilent);

    /// <summary>Пара ECH от `xray tls ech`: ConfigList кладут в ссылку (ech=), ServerKeys читает сервер (echServerKeys).</summary>
    static (string ConfigList, string ServerKeys) XrayEch(Xray xray)
    {
        string output = XrayRun(xray, "tls ech --serverName docs.example.net").Output;
        var lines = output.Split((char)10).Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        int list = lines.IndexOf("ECH config list:"), keys = lines.IndexOf("ECH server keys:");
        Check(list >= 0 && keys >= 0 && list + 1 < lines.Count && keys + 1 < lines.Count, "xray tls ech must print a config list and server keys: " + output);
        return (lines[list + 1], lines[keys + 1]);
    }

    /// <summary>Открытый ключ Reality из `xray x25519` (закрытый нужен серверу).</summary>
    static (string Private, string Public) RealityKeys(Xray xray)
    {
        string output = XrayRun(xray, "x25519").Output;
        var privateKey = Regex.Match(output, @"PrivateKey: (\S+)");
        var publicKey = Regex.Match(output, @"PublicKey\): (\S+)");
        Check(privateKey.Success && publicKey.Success, "xray x25519 must print a key pair: " + output);
        return (privateKey.Groups[1].Value, publicKey.Groups[1].Value);
    }

    /// <summary>Сервер Xray запускается как есть. Ждёт «started», вывод копится в log. Убитый загрузчиком процесс запускается заново.</summary>
    static Process StartXrayProcess(string exe, string config, string dir, StringBuilder log) =>
        UntilLoaded("the Xray server", () =>
        {
            lock (log) log.Clear();
            var server = new Process
            {
                StartInfo = new ProcessStartInfo(exe, "run -c \"" + config + "\"")
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true, WorkingDirectory = dir,
                },
            };
            server.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (log) log.AppendLine(e.Data); };
            server.OutputDataReceived += (s, e) => { if (e.Data != null) lock (log) log.AppendLine(e.Data); };
            server.Start();
            server.BeginErrorReadLine();
            server.BeginOutputReadLine();
            var wait = Stopwatch.StartNew();
            while (wait.ElapsedMilliseconds < 20000 && !server.HasExited) { lock (log) if (log.ToString().Contains(" started")) break; Thread.Sleep(50); }
            return server;
        }, server =>
        {
            if (!server.HasExited) return false;
            server.WaitForExit();
            lock (log) return server.ExitCode == LoaderStatus && log.Length == 0;
        });

    /// <summary>
    /// Настоящий сервер Xray с XHTTP на localhost. Link - ссылка, по которой к нему подключается Zarp. Варианты: none, packet-up,
    /// tls-stream-up, tls-stream-one, tls-extra, reality, reality-stream-up. Reality нужен сервер, на который он перенаправляет чужих: dest.
    /// </summary>
    static LoopbackServer StartXrayServer(SingBox box, Xray xray, string variant, LoopbackServer dest = null)
    {
        string dir = Path.Combine(_data, "xray-server-" + variant);
        Directory.CreateDirectory(dir);
        // серверу нужен свой экземпляр exe: Xray.Stop() останавливает все процессы по пути, в том числе его
        string serverExe = Path.Combine(dir, "xray.exe");
        File.Copy(xray.Exe, serverExe, true);

        int port = FreeTcpPort();
        bool tls = variant.StartsWith("tls"), reality = variant.StartsWith("reality");
        string baseLink = "vless://" + TestUuid + "@127.0.0.1:" + port + "?type=xhttp&path=%2Fxh";
        string mode = variant.EndsWith("stream-up") ? "stream-up" : variant.EndsWith("stream-one") ? "stream-one" : variant == "packet-up" ? "packet-up" : "auto";
        var stream = new Dictionary<string, object>
        {
            ["network"] = "xhttp", ["security"] = tls ? "tls" : reality ? "reality" : "none",
            ["xhttpSettings"] = new Dictionary<string, object> { ["path"] = "/xh", ["mode"] = "auto" },
        };
        string link, echList = null;
        if (tls)
        {
            var pem = SingBoxRun(box, "generate tls-keypair localhost").Output;
            string key = Regex.Match(pem, "-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", RegexOptions.Singleline).Value;
            string cert = Regex.Match(pem, "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOptions.Singleline).Value;
            Check(key.Length > 0 && cert.Length > 0, "sing-box must generate a test certificate");
            File.WriteAllText(Path.Combine(dir, "cert.pem"), cert.Replace("\r", ""));
            File.WriteAllText(Path.Combine(dir, "key.pem"), key.Replace("\r", ""));
            // Xray читает сертификат по абсолютному пути; закрепляется хеш самого сертификата
            stream["tlsSettings"] = new Dictionary<string, object>
            {
                ["certificates"] = new List<object> { new Dictionary<string, object> { ["certificateFile"] = Path.Combine(dir, "cert.pem"), ["keyFile"] = Path.Combine(dir, "key.pem") } },
                ["alpn"] = new List<object> { "h2" },
            };
            var der = Convert.FromBase64String(string.Concat(cert.Replace("\r", "").Split('\n').Where(l => !l.StartsWith("-----"))));
            string pin;
            using (var sha = SHA256.Create()) pin = string.Concat(sha.ComputeHash(der).Select(b => b.ToString("x2")));
            link = baseLink + "&security=tls&sni=localhost&alpn=h2&pcs=" + pin + "&mode=" + mode;
            if (variant == "tls-extra")
                link += "&extra=" + Uri.EscapeDataString("{\"xPaddingBytes\":\"100-1000\",\"xmux\":{\"maxConcurrency\":\"16-32\",\"cMaxReuseTimes\":\"64-128\"},\"noGRPCHeader\":false}");
            // padding без extra, как его пишут панели для клиентов на sing-box (x_padding_bytes)
            if (variant == "tls-padding") link += "&x_padding_bytes=100-1000";
            // ECH: ключи на сервере, конфигурация в ссылке (Xray с 26.5 требует ECH от клиента, у которого он задан)
            if (variant == "tls-ech")
            {
                var ech = XrayEch(xray);
                ((Dictionary<string, object>)stream["tlsSettings"])["echServerKeys"] = ech.ServerKeys;
                link += "&ech=" + Uri.EscapeDataString(ech.ConfigList);
                echList = ech.ConfigList;
            }
        }
        else if (reality)
        {
            Check(dest != null, "Reality needs a server to forward strangers to");
            var keys = RealityKeys(xray);
            int destPort = int.Parse(Regex.Match(dest.Link, @"@127\.0\.0\.1:(\d+)").Groups[1].Value);
            stream["realitySettings"] = new Dictionary<string, object>
            {
                ["show"] = false, ["target"] = "127.0.0.1:" + destPort, ["serverNames"] = new List<object> { "localhost" },
                ["privateKey"] = keys.Private, ["shortIds"] = new List<object> { "0123abcd" },
            };
            link = baseLink + "&security=reality&pbk=" + keys.Public + "&sid=0123abcd&sni=localhost&fp=chrome&spx=%2F&mode=" + mode;
        }
        else link = baseLink + "&mode=" + mode;

        var config = new Dictionary<string, object>
        {
            ["log"] = new Dictionary<string, object> { ["loglevel"] = "warning", ["access"] = "none" },
            ["inbounds"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["tag"] = "in", ["listen"] = "127.0.0.1", ["port"] = port, ["protocol"] = "vless",
                    ["settings"] = new Dictionary<string, object>
                    {
                        ["users"] = new List<object> { new Dictionary<string, object> { ["id"] = TestUuid } }, ["decryption"] = "none",
                    },
                    ["streamSettings"] = stream,
                },
            },
            // с 26.5 выход freedom по умолчанию не пускает в частные и служебные адреса, а страница для проверки живёт на 127.0.0.1
            ["outbounds"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["tag"] = "direct", ["protocol"] = "freedom",
                    ["settings"] = new Dictionary<string, object>
                    {
                        ["finalRules"] = new List<object> { new Dictionary<string, object> { ["action"] = "allow", ["ip"] = new List<object> { "127.0.0.0/8" } } },
                    },
                },
            },
        };
        string serverConfig = Path.Combine(dir, "server.json");
        File.WriteAllText(serverConfig, new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(config));
        var serverCheck = UntilLoaded("Xray", () => Sync(() => ProcessUtil.RunAsync(serverExe, "run -test -c \"" + serverConfig + "\"", 30000)), LoaderKilled);
        Check(serverCheck.Ok, "The test server configuration must be valid:\n" + serverCheck.Output);

        var result = new LoopbackServer { Link = link, Ech = echList };
        result.Process = StartXrayProcess(serverExe, serverConfig, dir, result.Log);
        lock (result.Log) Check(!result.Process.HasExited && result.Log.ToString().Contains(" started"), "The test server must start:\n" + result.Log);
        return result;
    }

    static string ConfigsOf(SingBox box, Xray xray) =>
        string.Join(",", new[] { Path.Combine(box.Dir, "config.json"), Path.Combine(xray.Dir, "config.json") }.Where(File.Exists));

    /// <summary>
    /// Поднимает на localhost настоящий сервер Xray с XHTTP и подключается к нему так же, как программа: мост Xray и sing-box
    /// с проверочным входом. Через цепочку проходят TCP и UDP, а проверка соединения доходит до страницы за сервером.
    /// </summary>
    static void TestXrayLoopback(string variant) => WithEmbeddedEngines((box, xray) =>
    {
        var runtime = new ProxyRuntime(box, xray);
        using (var web = new FakeServer(new byte[64 * 1024]))
        using (var dest = variant.StartsWith("reality") ? StartLoopbackServer(box, "trojan") : null)
        using (var server = StartXrayServer(box, xray, variant, dest))
        {
            try
            {
                var profile = ProxyProfile.Parse(server.Link);
                Check(profile.UsesXray, "Setup: the link is XHTTP");
                var session = runtime.NewSession(profile);
                session.Address = "127.0.0.1";
                var err = StartRuntime(runtime, session);
                Check(err == null, variant + ": the session must start: " + err + "\n" + xray.ReadLog() + "\n" + box.ReadLog());
                Check(box.Running && xray.Running && runtime.Running, "sing-box and the bridge run");
                Check(ConfigsOf(box, xray) == "", "The configurations with the UUID and the passwords are deleted once both programs run: " + ConfigsOf(box, xray));

                int webPort = int.Parse(web.Url("/").Split(':')[2].TrimEnd('/'));
                string response = HttpThroughSocks(session.Port, webPort, session.User, session.Password);
                Check(response.StartsWith("HTTP/1.1 200") && response.Length > 64 * 1024, variant + ": TCP traffic must pass through the server, got " + response.Length + " bytes");
                Check(UdpThroughSocks(session.Port, session.User, session.Password) == "zarp-udp", variant + ": UDP traffic must pass through the server");

                // проверка соединения, как в программе: запросы по IP-адресу и по имени (имя разбирает сервер)
                int before = web.Requests;
                SetPrivate(runtime, "TraceUrl", web.Url("/trace"));
                var good = Sync(() => runtime.MeasureAsync(session, 2, 15000, CancellationToken.None));
                Check(good.Ok && good.Failed == 0 && web.Requests == before + 3, variant + ": the check must reach the page, ok=" + good.Ok + ", failed=" + good.Failed + ", " + good.Error);
                SetPrivate(runtime, "TraceUrl", web.Url("/trace").Replace("127.0.0.1", "localhost"));
                var byName = Sync(() => runtime.MeasureAsync(session, 1, 15000, CancellationToken.None));
                Check(byName.Ok, variant + ": the check must also work with a name instead of an address, " + byName.Error);

                // соединение Xray с сервером видно в таблице системы; по нему ручной тест с настоящим адаптером находит петлю (см. RealAdapterTests)
                var xrayIds = ProcessIds("xray", xray.Exe);
                Check(xrayIds.Count > 0 && ProcessIds("sing-box", box.Exe).Count > 0, "Setup: both programs are found by their path");
                bool visible = false;
                for (int i = 0; i < 15 && !visible; i++)
                {
                    HttpThroughSocks(session.Port, webPort, session.User, session.Password);
                    visible = TcpRows().Any(r => r.State == 5 && r.RemotePort == profile.Port && xrayIds.Contains(r.Pid) && r.Remote.Equals(IPAddress.Loopback) &&
                                                 InterfaceOf(r.Local) != null && InterfaceOf(r.Local) != SingBox.TunName);
                    if (!visible) Thread.Sleep(200);
                }
                Check(visible, variant + ": the connection of the bridge to the server must be visible in the TCP table, on an interface other than " + SingBox.TunName);

                // мост закрыт для чужих: нужен случайный пароль сессии
                Check(Catch(() => new Socks5Session(session.XrayPort, session.XrayUser, "wrong")) is IOException, "The bridge must refuse a wrong password");
                Check(Catch(() => SocksWithoutPassword(session.XrayPort)) is IOException, "The bridge must refuse a client that offers no password");
                Check(Catch(() => new Socks5Session(session.Port, "zarp", session.XrayPassword)) is IOException, "The two passwords are not interchangeable");
            }
            finally { runtime.Stop(); }
        }
        Check(!box.Running && !xray.Running && !runtime.Running, "Stop must end sing-box and the bridge");
    });

    /// <summary>ECH у XHTTP тоже настоящий: с чужим списком (и без ECH на сервере) клиент не подключается, с верным подключается (TestXrayLoopback[tls-ech]).</summary>
    static void TestXrayEchIsEnforced() => WithEmbeddedEngines((box, xray) =>
    {
        var runtime = new ProxyRuntime(box, xray);
        using (var web = new FakeServer(new byte[16]))
        using (var server = StartXrayServer(box, xray, "tls-ech"))
        {
            try
            {
                Check(!string.IsNullOrEmpty(server.Ech), "The test server has ECH");
                string spoiled = server.Link.Replace(Uri.EscapeDataString(server.Ech), Uri.EscapeDataString(XrayEch(xray).ConfigList));
                Check(spoiled != server.Link, "The link must change");
                var session = runtime.NewSession(ProxyProfile.Parse(spoiled));
                session.Address = "127.0.0.1";
                Check(StartRuntime(runtime, session) == null, "The session must start");
                SetPrivate(runtime, "TraceUrl", web.Url("/trace"));
                var m = Sync(() => runtime.MeasureAsync(session, 1, 8000, CancellationToken.None));
                Check(!m.Ok && web.Requests == 0, "A wrong ECH list must break the connection, ok=" + m.Ok);
                runtime.Stop();

                // с верным списком то же самое подключение работает
                session = runtime.NewSession(ProxyProfile.Parse(server.Link));
                session.Address = "127.0.0.1";
                Check(StartRuntime(runtime, session) == null, "The session with the right list must start");
                var ok = Sync(() => runtime.MeasureAsync(session, 1, 10000, CancellationToken.None));
                Check(ok.Ok, "The right ECH list must connect: " + ok.Error);
            }
            finally { runtime.Stop(); }
        }
    });

    /// <summary>Сервер, которого нет, и ошибки: причина видна в журнале, путь XHTTP в него не попадает, остановка убирает журнал Xray.</summary>
    static void TestXrayDiagnostics() => WithEmbeddedEngines((box, xray) =>
    {
        var runtime = new ProxyRuntime(box, xray);
        using (var web = new FakeServer(new byte[16]))
        {
            try
            {
                int dead = FreeTcpPort();
                var session = runtime.NewSession(ProxyProfile.Parse("vless://" + TestUuid + "@127.0.0.1:" + dead + "?type=xhttp&path=%2Fsecret-path"));
                session.Address = "127.0.0.1";
                var err = StartRuntime(runtime, session);
                Check(err == null, "A bridge to a server that is not there still starts: " + err);
                SetPrivate(runtime, "TraceUrl", web.Url("/trace"));
                var clock = Stopwatch.StartNew();
                var m = Sync(() => runtime.MeasureAsync(session, 1, 10000, CancellationToken.None));
                Check(!m.Ok && m.Failed == 2 && web.Requests == 0 && clock.Elapsed.TotalSeconds < 9, "A dead server fails the check quickly, ok=" + m.Ok + ", failed=" + m.Failed + ", " + clock.Elapsed.TotalSeconds + " s");
                string raw = xray.ReadLog();
                string why = runtime.LastError();
                Check(raw.Contains("secret-path"), "Setup: the detailed log of Xray does hold the path of the link: " + raw);
                Check(why != null && why.Contains(":" + dead) && !why.Contains("secret-path") && !why.Contains("http://") && !why.Contains(TestUuid), "The reason is shown without the path and the page addresses: " + why);
                runtime.Stop();
                // журнал sing-box остаётся (его очищает следующий запуск), поэтому после остановки проверяется именно Xray
                Check(!File.Exists(xray.LogFile) && xray.LastError() == null, "Stopping removes the log of Xray: a later failure never shows an old reason; the file exists: " + File.Exists(xray.LogFile) + ", last error: " + xray.LastError());

                // сессия с адаптером пишет только предупреждения
                session = runtime.NewSession(ProxyProfile.Parse("vless://" + TestUuid + "@127.0.0.1:" + dead + "?type=xhttp&path=%2Fsecret-path"));
                session.Address = "127.0.0.1";
                session.Tun = true; // конфигурация с адаптером; sing-box здесь запускать нельзя, поэтому только мост
                var bridgeOnly = StartBridgeOnly(xray, XrayConfig.Build(session), session.XrayPort);
                Check(bridgeOnly == null, "The bridge starts alone: " + bridgeOnly);
                using (var s = new Socks5Session(session.XrayPort, session.XrayUser, session.XrayPassword))
                {
                    s.RequestHost(1, "must-not-be-logged.example", 443);
                    Thread.Sleep(500);
                }
                Check(!xray.ReadLog().Contains("must-not-be-logged") && !xray.ReadLog().Contains("secret-path"), "While the user's traffic flows Xray logs no addresses: " + xray.ReadLog());
                xray.Stop();
            }
            finally { runtime.Stop(); }
        }
    });

    /// <summary>Конфигурации Xray и sing-box для моста принимают сами программы; испорченную отвергают, причина читается.</summary>
    static void TestXrayConfigsAccepted() => WithEmbeddedEngines((box, xray) =>
    {
        string verify = Regex.Match(XrayRun(xray, "mldsa65").Output, @"Verify\W+(\S+)").Groups[1].Value;
        Check(verify.Length > 100, "xray mldsa65 must print a public key: " + verify);
        string reality = XhttpBase + "type=xhttp&security=reality&pbk=" + TestRealityKey + "&sid=0123abcd&sni=www.example.org";
        string download = Uri.EscapeDataString("{\"downloadSettings\":{\"address\":\"203.0.113.9\",\"port\":443,\"network\":\"xhttp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"d.example\",\"alpn\":[\"h2\"]},\"xhttpSettings\":{\"path\":\"/dl\",\"mode\":\"auto\"}}}");
        var links = new[]
        {
            XhttpBase + "type=xhttp",
            XhttpBase + "type=xhttp&path=%2Fa&host=front.example&mode=packet-up",
            XhttpBase.Replace("@x.example", "@[2001:db8::1]") + "type=xhttp&security=tls&sni=s.example",
            XhttpBase + "type=xhttp&security=tls&sni=s.example&alpn=h2,http/1.1&fp=chrome&pcs=" + HexPin + "&vcn=s.example&mode=stream-up&path=%2Fp",
            XhttpBase + "type=xhttp&security=tls&alpn=h3&mode=stream-one",
            XhttpBase + "type=xhttp&security=tls&pcs=" + string.Join(":", Enumerable.Repeat("AB", 32)) + "," + HexPin,
            XhttpBase + "type=xhttp&security=tls&sni=s.example&alpn=h2&x_padding_bytes=100-1000&ech=" + Uri.EscapeDataString(XrayEch(xray).ConfigList),
            reality,
            reality + "&fp=firefox&spx=%2Fa%3Fp%3D1-3&mode=stream-up&host=front.example",
            reality + "&pqv=" + verify,
            XhttpBase + "type=xhttp&extra=" + Uri.EscapeDataString("{\"xPaddingBytes\":\"100-1000\",\"xmux\":{\"maxConcurrency\":\"16-32\",\"cMaxReuseTimes\":\"64-128\"},\"noGRPCHeader\":false,\"scMaxEachPostBytes\":\"500000-1000000\",\"headers\":{\"X-Test\":\"1\"}}"),
            XhttpBase + "type=xhttp&security=tls&extra=" + download,
        };
        foreach (var link in links)
        foreach (bool tun in new[] { false, true })
        {
            var session = XhttpSession(ProxyProfile.Parse(link), tun);
            string tag = link.Substring(XhttpBase.Length, Math.Min(60, link.Length - XhttpBase.Length)) + " tun=" + tun;
            var check = Sync(() => xray.CheckAsync(XrayConfig.Build(session)));
            if (LoaderKilled(check)) check = Sync(() => xray.CheckAsync(XrayConfig.Build(session)));
            Check(check.Ok, "Xray must accept the configuration for " + tag + ":\n" + check.Output);
            var boxCheck = SingBoxRun(box, "check -c " + WriteTemp(ProxyConfig.Build(session)));
            Check(boxCheck.Ok, "sing-box must accept the configuration with the bridge for " + tag + ":\n" + boxCheck.Output);
        }
        Check(Directory.GetFiles(xray.Dir, "check-*.json").Length == 0, "Checking leaves no file with the configuration behind");

        // испорченная конфигурация отвергается, причина читается, служебные строки программы в сообщение не попадают
        string good = XrayConfig.Build(XhttpSession(ProxyProfile.Parse(links[1]), false));
        string broken = good.Replace("\"mode\":\"packet-up\"", "\"mode\":\"bogus\"");
        var bad = Sync(() => xray.CheckAsync(broken));
        Check(broken != good && !bad.Ok && bad.Output.Contains("unsupported mode: bogus"), "A bad mode must be refused by Xray: " + bad.Output);
        string shown = (string)typeof(ProxyRuntime).GetMethod("ShortenXray", PrivateStatic).Invoke(null, new object[] { bad.Output });
        Check(shown.Contains("unsupported mode: bogus") && !shown.Contains("Penetrates") && !shown.Contains("go1.") && !shown.Contains("check-") && shown.Length <= 403, "The reason is shown without the banner of the program: " + shown);
        Check(!Sync(() => xray.CheckAsync("{")).Ok && !Sync(() => xray.CheckAsync("{\"outbounds\":[{\"protocol\":\"nope\"}]}")).Ok, "Garbage and an unknown protocol are refused");

        // программа отвергает то, что приняла ссылка: ProxyRuntime.StartAsync называет Xray и причину и ничего не оставляет работать
        var runtime = new ProxyRuntime(box, xray);
        var session2 = runtime.NewSession(ProxyProfile.Parse(XhttpBase + "type=xhttp&security=tls&fp=no-such-print"));
        session2.Address = "127.0.0.1";
        var err = StartRuntime(runtime, session2);
        Check(err != null && err.Key == "err.xrayConfig" && ((string)err.Args[0]).Contains("no-such-print") && !((string)err.Args[0]).Contains("Penetrates") && !xray.Running && !box.Running && runtime.LastError() == null,
            "A configuration that Xray refuses is reported by name, without the banner of the program, and nothing is left running: " + err);

        // Xray, который запустился и сразу упал: в сообщении хвост его журнала, ничего не осталось работать и в папке нет конфигурации
        var crashed = StartBridgeOnly(xray, "{ not json", FreeTcpPort());
        Check(crashed != null && crashed.Key == "err.xrayExited" && ((string)crashed.Args[0]).Contains("Failed to start") && !xray.Running && !File.Exists(Path.Combine(xray.Dir, "config.json")),
            "A bridge that dies at once is reported with the end of its log: " + crashed);
    });

    /// <summary>Что из журнала Xray попадает в сообщение об ошибке: последняя строка о неудаче, без времени, номера соединения и адресов страниц.</summary>
    static void TestXrayLog()
    {
        var xray = new Xray(Path.Combine(_data, "xray-log"));
        Directory.CreateDirectory(xray.Dir);
        string Last(string log) { File.WriteAllText(xray.LogFile, log); return xray.LastError(); }
        string head = "Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.5 windows/amd64)\r\nA unified platform for anti-censorship.\r\n" +
                      "2026/10/11 03:01:14.264208 [Info] infra/conf/serial: Reading config: &{Name:config.json Format:json}\r\n" +
                      "2026/10/11 03:01:14.278208 [Warning] core: Xray 26.7.28 started\r\n";
        Check(xray.LastError() == null && xray.ReadLog() == "", "No log, no reason");
        Check(Last(head) == null && Last("") == null, "A quiet start has no failure");
        string info = "2026/10/11 03:01:15.870104 [Info] [289985034] transport/internet/splithttp: failed to GET http://127.0.0.1/secret/abc > Get \"http://127.0.0.1/secret/abc\": " +
                      "dial tcp 127.0.0.1:39099: connectex: No connection could be made because the target machine actively refused it.\r\n";
        string got = Last(head + info);
        Check(got == "transport/internet/splithttp: failed to GET <url> > Get \"<url>\": dial tcp 127.0.0.1:39099: connectex: No connection could be made because the target machine actively refused it.",
            "The reason has no time, no connection number and no page address: " + got);
        string tunnelling = "2026/10/11 03:01:15.871104 [Info] [289985034] proxy/vless/outbound: tunneling request to tcp:a.example:443 via 127.0.0.1:39099\r\n";
        Check(Last(head + info + tunnelling) == got, "Lines that are not about a failure do not hide the reason");
        Check(Last(head + info + "2026/10/11 03:01:16.000000 [Error] app/x: broken\r\n") == "app/x: broken", "The last failure wins, and errors count");
        Check(Last(head + "2026/10/11 03:01:16.000000 [Warning] app/y: something odd\r\n") == "app/y: something odd", "Warnings count");
        Check(Last(head + "2026/10/11 03:01:16.000000 [Debug] app/z: failed\r\n") == null && Last(head + "2026/10/11 03:01:16.000000 [Info] app/z: fine\r\n") == null, "Other levels and quiet lines are ignored");
        Check(Last(head + "panic: failed something\r\n") == null && Last(head + "failed\r\n2026/10/11 broken [Error] line\r\n") == null, "Lines that are not in the format of the log are ignored");
        got = Last(head + "2026/10/11 03:01:16.000000 [Error] big: " + new string('x', 500) + "\r\n");
        Check(got.Length == 303 && got.EndsWith("..."), "A long line is cut: " + got.Length);
        Check(Last(head + "2026/10/11 03:01:16.000000 [Error] first\r\n2026/10/11 03:01:16.100000 [Error] second\n") == "second", "A log with plain line feeds is read too");
        // журнал читается, пока им владеет работающий процесс: достаточно разрешения на запись для других
        using (var holder = new FileStream(xray.LogFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            Check(xray.ReadLog().Contains("second"), "The log can be read while the program keeps it open");
    }

    static void TestShortenXray()
    {
        string Shorten(string text) => (string)typeof(ProxyRuntime).GetMethod("ShortenXray", PrivateStatic).Invoke(null, new object[] { text });
        string banner = "Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.5 windows/amd64)\r\nA unified platform for anti-censorship.\r\n";
        Check(Shorten(banner + "Failed to start: main: failed to load config files: [check-0123.json] > infra/conf: failed to build outbound config with tag server > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build XHTTP config. > infra/conf: unsupported mode: bogus\r\n")
              == "infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build XHTTP config. > infra/conf: unsupported mode: bogus", "Only the last three links of the chain are kept");
        Check(Shorten(banner + "Failed to start: main: bad") == "main: bad" && Shorten("just text") == "just text" && Shorten(null) == "" && Shorten("") == "", "Short and unusual outputs pass through");
        string longText = "Failed to start: " + string.Join(" > ", Enumerable.Repeat(new string('x', 200), 5));
        Check(Shorten(longText).Length == 403 && Shorten(longText).EndsWith("..."), "A very long reason is cut");
    }

    /// <summary>xray.exe запускается, только если файл побайтно совпадает со вшитым, как и sing-box.</summary>
    static void TestXrayTamper() => WithEmbeddedEngines((box, xray) =>
    {
        using (var file = new FileStream(xray.Exe, FileMode.Append)) file.WriteByte(0);
        var err = Sync(() => xray.StartAsync("{}", FreeTcpPort()));
        Check(err != null && err.Key == "err.xrayChanged" && !xray.Running, "An xray.exe that differs from the embedded one must not be started, got: " + err);
        Check(!File.Exists(Path.Combine(xray.Dir, "config.json")), "A refused start leaves no configuration (it may hold the UUID) behind");
        Check(xray.ExtractEmbedded() && xray.Installed, "Unpacking puts the genuine file back");
        var version = XrayRun(xray, "version");
        Check(version.Ok && version.Output.Contains(Xray.EmbeddedVersion.TrimStart('v')), "The restored Xray runs and reports the embedded version: " + version.Output);
        Check(!xray.ExtractEmbedded(), "An unchanged file is not written again");
        File.Delete(Path.Combine(xray.Dir, "version.txt"));
        Check(!xray.Installed && Sync(() => xray.StartAsync("{}", FreeTcpPort())).Key == "err.xrayMissing", "Without the version marker the program is treated as missing");
        Check(xray.ExtractEmbedded() && xray.Installed, "Unpacking restores the marker");
    });

    /// <summary>Жизненный цикл: запуск моста перед sing-box, остановка обоих, подхват после перезапуска Zarp, остатки.</summary>
    static void TestXrayLifecycle() => WithEmbeddedEngines((box, xray) =>
    {
        var runtime = new ProxyRuntime(box, xray);
        var profile = ProxyProfile.Parse("vless://" + TestUuid + "@127.0.0.1:" + FreeTcpPort() + "?type=xhttp");
        try
        {
            // sing-box не запустился (его файл подменён): мост, уже запущенный перед ним, не остаётся работать
            using (var file = new FileStream(box.Exe, FileMode.Append)) file.WriteByte(0);
            var session = runtime.NewSession(profile);
            session.Address = "127.0.0.1";
            var err = Sync(() => runtime.StartAsync(session, CancellationToken.None));
            Check(err != null && err.Key == "err.singboxChanged" && !xray.Running && !box.Running && !runtime.Running, "A failed start of sing-box takes the bridge down with it: " + err);
            Check(ConfigsOf(box, xray) == "", "A failed start leaves no configuration behind: " + ConfigsOf(box, xray));
            Check(box.ExtractEmbedded() && box.Installed, "Setup: sing-box is restored");

            // без Xray такие серверы не подключаются, и sing-box не запускается зря
            var withoutXray = new ProxyRuntime(box);
            session = withoutXray.NewSession(profile);
            session.Address = "127.0.0.1";
            err = Sync(() => withoutXray.StartAsync(session, CancellationToken.None));
            Check(err != null && err.Key == "err.xrayMissing" && !box.Running && !withoutXray.PrepareBridge(), "Without Xray an XHTTP server is refused before anything starts: " + err);
            // Xray есть в сборке, но не распакован (папка пуста): тот же отказ, без исключения о несуществующем файле
            var notUnpacked = new ProxyRuntime(box, new Xray(Path.Combine(_data, "xray-empty")));
            session = notUnpacked.NewSession(profile);
            session.Address = "127.0.0.1";
            err = Sync(() => notUnpacked.StartAsync(session, CancellationToken.None));
            Check(err != null && err.Key == "err.xrayMissing" && !box.Running && !notUnpacked.Bridge.Running, "A bridge that is not unpacked is reported as missing: " + err);

            // порт моста так и не открылся: срок вышел, мост остановлен, конфигурации не осталось
            SetPrivate(xray, "StartTimeoutMs", 2500);
            session = runtime.NewSession(profile);
            session.Address = "127.0.0.1";
            var slow = StartBridgeOnly(xray, XrayConfig.Build(session), FreeTcpPort()); // ждём порт, который никто не откроет
            Check(slow != null && slow.Key == "err.xrayTimeout" && !xray.Running && !File.Exists(Path.Combine(xray.Dir, "config.json")), "A bridge that never opens its port is stopped and reported: " + slow);
            SetPrivate(xray, "StartTimeoutMs", 25000);

            // обычный запуск
            session = runtime.NewSession(profile);
            session.Address = "127.0.0.1";
            err = StartRuntime(runtime, session);
            Check(err == null && box.Running && xray.Running, "Setup: both run: " + err);
            Check(box.RunningPid != 0 && File.Exists(Path.Combine(box.Dir, "session.json")), "sing-box records its session");
            Check(runtime.Intact && !runtime.BridgeLost, "With both programs running the chain is whole");
            Check(PortAccepts(session.XrayPort) && PortAccepts(session.Port), "Both local ports accept connections as soon as the start returns");
            Check(xray.LastError() == null && runtime.LastError() == null, "A quiet start has no failure to show: " + xray.LastError() + " / " + runtime.LastError());

            // подхват после перезапуска Zarp: новый ProxyRuntime на тех же папках видит сессию, если мост жив
            var restarted = new ProxyRuntime(new SingBox(box.Dir), new Xray(xray.Dir));
            var adopted = restarted.Adopt(profile);
            Check(adopted != null && adopted.Tun && adopted.Port == session.Port && adopted.User == session.User && adopted.Password == session.Password, "A running session is taken over after a restart");
            Check(restarted.Intact && !restarted.BridgeLost, "A taken-over session knows that it needs the bridge, and the bridge is there");
            Check(restarted.Adopt(ProxyProfile.Parse("vless://" + TestUuid + "@127.0.0.1:" + FreeTcpPort() + "?type=xhttp")) == null, "Another server is not taken over");
            Check(new ProxyRuntime(new SingBox(box.Dir)).Adopt(profile) == null, "Without a bridge program an XHTTP session cannot be taken over");
            xray.Stop();
            Check(!xray.Running && box.Running && runtime.Running && restarted.Adopt(profile) == null,
                "A session whose bridge is gone is not taken over, and sing-box left alone still counts as running (so that it gets stopped)");
            Check(!runtime.Intact && runtime.BridgeLost && !restarted.Intact && restarted.BridgeLost, "sing-box without its bridge is a broken connection, and the loss is named as the bridge's");
            runtime.Stop();
            Check(!box.Running && !xray.Running && !runtime.Running && !runtime.Intact && !runtime.BridgeLost, "Stop ends everything");
            Check(restarted.Adopt(profile) == null, "Nothing is taken over after Stop");

            // сессия сервера без XHTTP подхватывается и без Xray, и мост ей не нужен для целостности
            var plain = ProxyProfile.Parse("trojan://secret@127.0.0.1:" + FreeTcpPort() + "?sni=localhost&allowInsecure=1");
            var plainSession = runtime.NewSession(plain);
            plainSession.Address = "127.0.0.1";
            err = StartRuntime(runtime, plainSession);
            Check(err == null && !xray.Running && new ProxyRuntime(new SingBox(box.Dir)).Adopt(plain) != null, "A session without XHTTP does not need the bridge: " + err);
            Check(runtime.Intact && !runtime.BridgeLost, "Without a bridge in the chain sing-box alone is a whole connection");
            runtime.Stop();

            // один мост без sing-box: тоже остаток, его останавливает Stop
            session = runtime.NewSession(profile);
            session.Address = "127.0.0.1";
            Check(StartBridgeOnly(xray, XrayConfig.Build(session), session.XrayPort) == null && xray.Running && !box.Running && runtime.Running, "A bridge alone counts as running");
            Check(PortAccepts(session.XrayPort), "The port of the bridge accepts connections as soon as its start returns");
            Check(!runtime.Intact, "A bridge alone is not a connection");
            runtime.Stop();
            Check(!xray.Running && !runtime.Running, "Stop removes a bridge that was left alone");

            // чужой xray.exe (например, ядро другого VPN-клиента) не наш: Zarp не считает его своим и не останавливает
            using (var foreign = StartXrayServer(box, xray, "none"))
            {
                Check(!foreign.Process.HasExited && !xray.Running && !runtime.Running, "An xray.exe from another folder is not ours");
                runtime.Stop();
                xray.Stop();
                Check(!foreign.Process.HasExited, "Stopping the bridge never touches another xray.exe");
            }

            // отмена посреди запуска: мост, уже запущенный перед sing-box, не остаётся работать. Отмена приходит, когда sing-box
            // уже запущен и ещё ждёт свой порт; если он всё же успел открыть порт первым, попытка повторяется
            bool cancelled = false;
            for (int attempt = 0; attempt < 5 && !cancelled; attempt++)
            {
                session = runtime.NewSession(profile);
                session.Address = "127.0.0.1";
                using (var source = new CancellationTokenSource())
                {
                    var watcher = Task.Run(() =>
                    {
                        var wait = Stopwatch.StartNew();
                        // sing-box.exe работает и во время `sing-box check`, поэтому ждём, пока поднимется ещё и мост: проверка к тому времени закончена
                        while (wait.Elapsed.TotalSeconds < 20 && !(xray.Running && box.Running)) Thread.Sleep(2);
                        source.Cancel();
                    });
                    var failure = Catch(() => Sync(() => runtime.StartAsync(session, source.Token)));
                    watcher.Wait();
                    cancelled = failure is OperationCanceledException;
                    if (cancelled)
                        Check(!xray.Running && !box.Running && !runtime.Running, "A start cancelled after the bridge was up must not leave it running");
                }
                runtime.Stop();
            }
            Check(cancelled, "Setup: the start could be cancelled while sing-box was still starting");
        }
        finally { runtime.Stop(); }
    });

    /// <summary>Порт на 127.0.0.1 принимает соединение прямо сейчас (без ожидания).</summary>
    static bool PortAccepts(int port)
    {
        try
        {
            using (var tcp = new TcpClient())
            {
                var connect = tcp.ConnectAsync(IPAddress.Loopback, port);
                return connect.Wait(1000) && tcp.Connected;
            }
        }
        catch { return false; }
    }

    /// <summary>Движок с подменённым ProxyRuntime: мост нужен только XHTTP, отказы называют Xray.</summary>
    static async Task TestXhttpEngineAsync()
    {
        const string link = "vless://" + TestUuid + "@docs.example:8433?security=tls&type=xhttp&path=%2F";
        var engine = ProxyEngine(out var fake, link);
        engine.Config.StopAfterWorking = 1; // одна проверенная пара: ход подключения тот же, что у других серверов
        var profile = ProxyProfile.Parse(link);
        Check(engine.Xray.Dir == Path.Combine(engine.DataDir, "xray") && Path.GetFileName(engine.Xray.Exe) == "xray.exe", "Xray lives in its own folder of the data directory");
        var wired = NewEngine();
        Check(GetPrivate<ProxyRuntime>(wired, "Proxy").Bridge == wired.Xray && GetPrivate<ProxyRuntime>(wired, "Proxy").Box == wired.SingBox, "The runtime of the engine works with the Xray and sing-box of the engine");
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && fake.BridgePrepared >= 1 && fake.Started.All(s => s.Profile.UsesXray), "An XHTTP server prepares the bridge: " + engine.State + " " + engine.Detail);
        Check(fake.Started.Select(s => s.Tun).SequenceEqual(new[] { false, false, false, true }), "The flow is the same as for the other servers");

        // другие серверы Xray не трогают: он даже не распаковывается
        engine = ProxyEngine(out fake);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && fake.BridgePrepared == 0, "A server that is not XHTTP never prepares the bridge, prepared " + fake.BridgePrepared);

        // Xray нет в этой сборке
        engine = ProxyEngine(out fake, link);
        fake.BridgeResult = () => false;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.xrayMissing") && fake.Started.Count == 0, "A build without Xray says so and starts nothing: " + engine.Detail);

        // антивирус заблокировал xray.exe: спрашивается исключение для папки Xray; отказ называет Xray
        engine = ProxyEngine(out fake, link);
        fake.BridgeResult = () => throw new AntivirusBlockedException("The antivirus blocked the file xray.exe", new IOException());
        string asked = null;
        engine.AskAntivirusExclusion = dir => { asked = dir; return false; };
        await engine.ConnectAsync();
        Check(asked == engine.Xray.Dir && engine.State == EngineState.Idle && engine.Detail == L.T("detail.avBlockedXray") && fake.Started.Count == 0 && fake.BridgePrepared == 1,
            "The folder of Xray is offered to the antivirus and a refusal names Xray: asked '" + asked + "', " + engine.Detail);

        // прочая ошибка распаковки
        engine = ProxyEngine(out fake, link);
        fake.BridgeResult = () => throw new IOException("disk full");
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.xrayMissing") && fake.Started.Count == 0, "Any other failure to unpack Xray is reported too: " + engine.Detail);

        // подхват после перезапуска: сессия XHTTP, у которой нет моста, не подхватывается (это решает ProxyRuntime.Adopt), остатки останавливаются
        engine = ProxyEngine(out fake, link);
        fake.IsRunning = true;
        fake.AdoptResult = null;
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && fake.Stops > 0, "Leftovers of a session that cannot be taken over are stopped");
        Check(profile.UsesXray, "Setup: the profile is XHTTP");

        // мост пропал при живом sing-box: адаптер остался бы без сервера и забрал весь трафик, поэтому остатки сразу останавливаются
        engine = ProxyEngine(out fake, link);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && fake.IsRunning, "Setup: connected");
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Connected, "A whole chain stays connected under observation");
        int stops = fake.Stops;
        fake.BridgeDied = true;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("detail.xrayFailed") && !fake.IsRunning && fake.Stops > stops,
            "A vanished bridge is named and the adapter that was left without it is removed: " + engine.State + " " + engine.Detail);
        fake.BridgeDied = false;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.disconnected"), "The next observation says disconnected: " + engine.Detail);

        // а когда исчез sing-box, виноват он, даже если мост ещё жив
        engine = ProxyEngine(out fake, link);
        await engine.ConnectAsync();
        fake.IsRunning = false;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("detail.singboxFailed"), "A vanished sing-box is still named as sing-box: " + engine.Detail);
    }
}
