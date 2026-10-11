using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Zarp.Core;

// Режим «свой сервер» - zapret2 плюс эндпоинт: пары «стратегия + сервер», перехват winws2 соединения с сервером.
// Настоящий winws2 запускается только с --dry-run и --wf-save (они не открывают WinDivert); сам перехват здесь проверить нельзя.
static partial class Program
{
    const string TcpServerLink = "trojan://secret@tcp.example:443?sni=front.example";
    const string QuicServerLink = "hysteria2://secret@udp.example:5443?sni=front.example";

    static void TestServerPairs()
    {
        var catalog = StrategyCatalog.BuiltInStrategies.ToList();
        int tlsCount = catalog.Count(s => s.Transport == WarpTransport.MasqueH2), quicCount = catalog.Count(s => s.Transport == WarpTransport.MasqueH3);
        Check(tlsCount > 0 && quicCount > 0 && tlsCount + quicCount == catalog.Count, "Setup: the built-in strategies are TLS and QUIC ones");

        // какой транспорт у сервера: от него зависит, какие стратегии ему подходят
        string realityKey = TestRealityKey;
        var transports = new[]
        {
            (TcpServerLink, WarpTransport.MasqueH2, "Trojan over TLS"),
            ("vless://" + TestUuid + "@h.example:443?security=tls&sni=h.example", WarpTransport.MasqueH2, "VLESS with TLS"),
            ("vless://" + TestUuid + "@h.example:443?security=reality&pbk=" + realityKey + "&sni=www.example.org", WarpTransport.MasqueH2, "VLESS Reality"),
            ("vless://" + TestUuid + "@h.example:443?type=ws&security=tls&path=%2Fw", WarpTransport.MasqueH2, "WebSocket"),
            ("vless://" + TestUuid + "@h.example:443?type=grpc&serviceName=s&security=tls", WarpTransport.MasqueH2, "gRPC"),
            ("trojan://secret@h.example:443?alpn=h3", WarpTransport.MasqueH2, "ALPN h3 does not make a TCP protocol QUIC"),
            (QuicServerLink, WarpTransport.MasqueH3, "Hysteria2"),
            ("hy2://secret@udp.example:443/?obfs=salamander&obfs-password=k", WarpTransport.MasqueH3, "Hysteria2 with Salamander"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls", WarpTransport.MasqueH2, "XHTTP"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls&alpn=h3", WarpTransport.MasqueH3, "XHTTP over QUIC"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls&alpn=h3,", WarpTransport.MasqueH3, "XHTTP over QUIC with a trailing comma in the ALPN"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls&alpn=%20h3%20", WarpTransport.MasqueH3, "XHTTP over QUIC with spaces in the ALPN"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls&alpn=h2,http/1.1", WarpTransport.MasqueH2, "XHTTP over HTTP/2"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=tls&alpn=h3,h2", WarpTransport.MasqueH2, "XHTTP that also offers HTTP/2"),
            ("vless://" + TestUuid + "@h.example:443?type=xhttp&security=reality&pbk=" + realityKey, WarpTransport.MasqueH2, "XHTTP with Reality"),
        };
        foreach (var (link, expected, why) in transports)
            Check(ProxyProfile.Parse(link).OuterTransport == expected, why + ": " + expected);

        var tcp = ProxyProfile.Parse(TcpServerLink).ToStrategy();
        var quic = ProxyProfile.Parse(QuicServerLink).ToStrategy();

        // каждому серверу подходят стратегии его транспорта и только они
        var tcpPairs = ServerPairs.Build(catalog, new[] { tcp });
        var quicPairs = ServerPairs.Build(catalog, new[] { quic });
        Check(tcpPairs.Count == tlsCount && tcpPairs.All(p => p.Transport == WarpTransport.MasqueH2), "A TLS server gets the TLS strategies only: " + tcpPairs.Count + " of " + tlsCount);
        Check(quicPairs.Count == quicCount && quicPairs.All(p => p.Transport == WarpTransport.MasqueH3), "A QUIC server gets the QUIC strategies only: " + quicPairs.Count + " of " + quicCount);

        // пара - это и стратегия, и сервер
        var source = catalog.First(s => s.Transport == WarpTransport.MasqueH2);
        var pair = tcpPairs[0];
        Check(pair.Id == source.Id + "@" + tcp.Id && pair.Id == ServerPairs.Id(source, tcp) && pair.Args == source.Args && pair.Transport == source.Transport && pair.Countries == source.Countries &&
              ReferenceEquals(pair.Profile, tcp.Profile) && pair.IsProxy && pair.UsesZapret && pair.Custom == source.Custom && pair.LegacyId == null && pair.ProtocolTitle == "Trojan",
            "A pair carries the strategy and the server: " + pair.Id);
        Check(pair.Name == "TLS: disorder on SNI points + Trojan: tcp.example:443", "A pair is named after the strategy without 'WARP' and the server: " + pair.Name);
        Check(!catalog.Any(s => s.IsProxy) && source.Profile == null, "The strategies the pairs are made of stay as they were");

        // порядок поиска: по стратегиям каталога, для каждой все подходящие серверы
        var both = ServerPairs.Build(catalog, new[] { tcp, quic });
        Check(both.Count == catalog.Count && both.Select(p => p.Id.Split('@')[0]).SequenceEqual(catalog.Select(s => s.Id)), "With a TLS and a QUIC server every strategy has exactly one server, in the order of the catalog");
        var twoTcp = ProxyProfile.Parse("trojan://secret@second.example:443").ToStrategy();
        var servers = new[] { tcp, quic, twoTcp };
        var order = ServerPairs.Build(catalog.Where(s => s.Transport == WarpTransport.MasqueH2).Take(2), servers);
        Check(order.Select(p => p.Id).SequenceEqual(new[]
        {
            catalog.First(s => s.Transport == WarpTransport.MasqueH2).Id + "@" + tcp.Id, catalog.First(s => s.Transport == WarpTransport.MasqueH2).Id + "@" + twoTcp.Id,
            catalog.Where(s => s.Transport == WarpTransport.MasqueH2).ElementAt(1).Id + "@" + tcp.Id, catalog.Where(s => s.Transport == WarpTransport.MasqueH2).ElementAt(1).Id + "@" + twoTcp.Id,
        }), "A strategy goes against all its servers before the next strategy: " + string.Join(", ", order.Select(p => p.Name)));

        // чему пара не подходит
        var wireGuard = new Strategy { Id = "wg", Name = "WG", Transport = WarpTransport.WireGuard, Args = "--payload=wireguard_initiation --lua-desync=fake:blob=zero64" };
        var plain = new Strategy { Id = "plain", Name = "plain", Transport = WarpTransport.MasqueH2, Args = "" };
        Check(ServerPairs.Build(new[] { wireGuard, plain }, servers).Count == 0, "A WireGuard strategy and a strategy without zapret2 make no pairs with a server");
        Check(ServerPairs.Build(tcpPairs, servers).Count == 0, "A pair is not a strategy that can be paired again");
        Check(ServerPairs.Build(catalog, new Strategy[0]).Count == 0 && ServerPairs.Build(new Strategy[0], servers).Count == 0, "No servers or no strategies, no pairs");
        Check(ServerPairs.Compatible(source, tcp.Profile) && !ServerPairs.Compatible(source, quic.Profile) && !ServerPairs.Compatible(wireGuard, tcp.Profile) && !ServerPairs.Compatible(pair, tcp.Profile),
            "Compatible follows the transport");

        // имена: «WARP » убирается только в начале слова, свои стратегии остаются как есть
        Check(ServerPairs.Short("WARP QUIC: fake") == "QUIC: fake" && ServerPairs.Short("★ My WARP") == "★ My WARP" && ServerPairs.Short("WARP") == "WARP" && ServerPairs.Short("WARPED x") == "WARPED x" &&
              ServerPairs.Short(" WARP x") == " WARP x" && ServerPairs.Short(null) == null && ServerPairs.Short("") == "", "Only the leading word WARP is dropped");
        var custom = new Strategy { Id = "custom-1", Name = "★ Mine", Transport = WarpTransport.MasqueH2, Args = "--payload=tls_client_hello --lua-desync=multisplit:pos=1", Custom = true, Countries = new[] { "ru" } };
        var customPair = ServerPairs.Build(new[] { custom }, new[] { tcp }).Single();
        Check(customPair.Name == "★ Mine + Trojan: tcp.example:443" && customPair.Custom && customPair.Countries.SequenceEqual(new[] { "ru" }), "A custom strategy joins in: " + customPair.Name);

        // стабильность: идентификатор не зависит ни от подписи сервера, ни от соседей; пропавший сервер уносит только свои пары
        var labelled = ProxyProfile.Parse(TcpServerLink + "#First name");
        var relabelled = ProxyProfile.Parse(TcpServerLink + "#Other name");
        Check(ServerPairs.Id(source, labelled.ToStrategy()) == ServerPairs.Id(source, relabelled.ToStrategy()), "A label does not change the identity of a pair");
        var ids = new HashSet<string>(both.Select(p => p.Id));
        var withoutQuic = ServerPairs.Build(catalog, new[] { tcp });
        Check(withoutQuic.All(p => ids.Contains(p.Id)) && withoutQuic.Count == tlsCount, "The pairs of the servers that stay keep their identity when another server goes");
        var many = Enumerable.Range(1, 200).Select(i => ProxyProfile.Parse("trojan://secret@s" + i + ".example:443").ToStrategy()).ToList();
        var manyPairs = ServerPairs.Build(catalog, many);
        Check(manyPairs.Count == 200 * tlsCount && manyPairs.Select(p => p.Id).Distinct().Count() == manyPairs.Count && manyPairs.Select(p => p.Name).Distinct().Count() == manyPairs.Count, "200 servers give 200 x " + tlsCount + " distinct pairs");

        // одинаковые подписи у разных серверов различаются в именах пар
        var named = Subscription.ToStrategies(new[] { ProxyProfile.Parse("trojan://a@x.example:443#Same"), ProxyProfile.Parse("trojan://b@y.example:443#Same") });
        var namedPairs = ServerPairs.Build(new[] { custom }, named);
        Check(namedPairs.Count == 2 && namedPairs[0].Name != namedPairs[1].Name, "Servers with the same label stay apart in the list: " + string.Join(" | ", namedPairs.Select(p => p.Name)));

        // страны: пара проходит фильтр по метке своей стратегии
        var tagged = ServerPairs.Build(catalog, new[] { tcp, quic });
        Check(StrategyFilter.Apply(tagged, "all").Count == tagged.Count && StrategyFilter.Apply(tagged, "cn").Count < tagged.Count && StrategyFilter.Apply(tagged, "ru").Count == tagged.Count,
            "The country filter works on pairs through their strategies");
    }

    static void TestServerTargetArgs()
    {
        var zapret = new Zapret(Path.Combine(_data, "server-args"));
        var tls = StrategyCatalog.BuiltInStrategies.First(s => s.Transport == WarpTransport.MasqueH2 && s.Args.Contains("tls_google"));
        var quicStrategy = StrategyCatalog.BuiltInStrategies.First(s => s.Transport == WarpTransport.MasqueH3 && s.Args.Contains("quic_google"));
        string RawFilter(List<string> args) => args.Where(a => a.StartsWith("--wf-raw-filter=")).Select(a => a.Substring("--wf-raw-filter=".Length)).Single();

        // TLS по TCP: порт сервера, адрес сервера, ничего лишнего
        var args = zapret.BuildArgs(tls, new ZapretTarget { Address = "203.0.113.7", Port = 8443 });
        Check(args.Contains("--wf-tcp-out=8443") && RawFilter(args) == "ip and (ip.DstAddr==203.0.113.7 or ip.SrcAddr==203.0.113.7)" && !args.Any(a => a.StartsWith("--wf-raw-part=")) &&
              !args.Any(a => a.StartsWith("--wf-filter-")), "TCP: the port of the server and its address in both directions: " + string.Join(" ", args));
        Check(args.Contains("--lua-init=@lua/zapret-lib.lua") && args.Contains("--lua-init=@lua/zapret-antidpi.lua") && args.Contains("--blob=tls_google:@files/fake/tls_clienthello_www_google_com.bin") &&
              !args.Any(a => a.StartsWith("--blob=quic_")), "The scripts and only the blobs that the strategy names are loaded: " + string.Join(" ", args));
        Check(!string.Join(" ", args).Contains("162.159") && !string.Join(" ", args).Contains("188.114") && !string.Join(" ", args).Contains("2606:4700"), "Nothing of the WARP ranges is left in the filter of a server");

        // QUIC: первый пакет к порту сервера
        var quicArgs = zapret.BuildArgs(quicStrategy, new ZapretTarget { Address = "203.0.113.7", Port = 5443, Quic = true });
        string part = quicArgs.Single(a => a.StartsWith("--wf-raw-part=")).Substring("--wf-raw-part=".Length);
        Check(part.StartsWith("outbound and udp and udp.DstPort==5443 and udp.PayloadLength>=256 and ") && part.Contains("udp.Payload[4]==1") && !quicArgs.Any(a => a.StartsWith("--wf-tcp-out")) &&
              RawFilter(quicArgs) == "ip and (ip.DstAddr==203.0.113.7 or ip.SrcAddr==203.0.113.7)" && quicArgs.Contains("--blob=quic_google:@files/fake/quic_initial_www_google_com.bin"),
            "QUIC: the first packet to the port of the server: " + part);

        // IPv6, адрес с областью и IPv4 в записи IPv6 приводятся к обычному виду
        Check(RawFilter(zapret.BuildArgs(tls, new ZapretTarget { Address = "2001:db8::7", Port = 443 })) == "ipv6 and (ipv6.DstAddr==2001:db8::7 or ipv6.SrcAddr==2001:db8::7)", "IPv6 uses the ipv6 fields");
        Check(RawFilter(zapret.BuildArgs(tls, new ZapretTarget { Address = "::ffff:203.0.113.7", Port = 443 })) == "ip and (ip.DstAddr==203.0.113.7 or ip.SrcAddr==203.0.113.7)", "An IPv4 address written as IPv6 is IPv4");
        var scoped = zapret.BuildArgs(tls, new ZapretTarget { Address = "fe80::1%12", Port = 443 });
        Check(RawFilter(scoped) == "ipv6 and (ipv6.DstAddr==fe80::1 or ipv6.SrcAddr==fe80::1)" && scoped.Contains("--wf-filter-lan=0"), "The scope of a link-local address is not part of the filter: " + RawFilter(scoped));

        // локальная сеть и loopback winws2 по умолчанию не трогает: для таких серверов это выключается
        foreach (var lan in new[] { "10.1.2.3", "172.16.0.9", "172.31.255.255", "192.168.1.5", "169.254.1.1", "fc00::1", "fd12::5", "fe80::1", "febf::1" })
        {
            var a = zapret.BuildArgs(tls, new ZapretTarget { Address = lan, Port = 443 });
            Check(a.Contains("--wf-filter-lan=0") && !a.Contains("--wf-filter-loopback=0"), lan + ": a server in the local network is intercepted too");
        }
        foreach (var global in new[] { "203.0.113.7", "172.15.255.255", "172.32.0.1", "192.169.0.1", "192.167.255.255", "169.253.255.255", "169.255.0.1", "11.0.0.1", "9.255.255.255", "100.64.0.1", "8.8.8.8", "2001:db8::1", "2a00:1450::1", "fec0::1", "fbff::1", "fe7f::1" })
            Check(!zapret.BuildArgs(tls, new ZapretTarget { Address = global, Port = 443 }).Any(a => a.StartsWith("--wf-filter-")), global + ": a public address needs no exception");
        foreach (var loopback in new[] { "127.0.0.1", "127.8.9.10", "::1" })
        {
            var a = zapret.BuildArgs(tls, new ZapretTarget { Address = loopback, Port = 443 });
            Check(a.Contains("--wf-filter-loopback=0") && !a.Contains("--wf-filter-lan=0"), loopback + ": a server on this computer is intercepted too");
        }

        // в фильтр попадает только IP-адрес: имя или подделка отвергаются
        foreach (var bad in new[] { "example.com", "", null, "203.0.113.7 or true", "1.2.3.4; 5.6.7.8", "203.0.113", "127.1", "999.1.1.1", "2001:db8::g", " 203.0.113.7", "203.0.113.7\n" })
            Check(Catch(() => zapret.BuildArgs(tls, new ZapretTarget { Address = bad, Port = 443 })) is ArgumentException, "Not an IP address: '" + bad + "'");
        Check(Catch(() => zapret.BuildArgs(tls, (ZapretTarget)null)) is ArgumentNullException, "No target, no arguments");

        // файл конфигурации: аргументы пары в кавычках, аргументы стратегии как есть в конце
        string config = zapret.BuildConfig(tls, new ZapretTarget { Address = "203.0.113.7", Port = 8443 });
        Check(config.StartsWith("'--wf-tcp-out=8443'\n'--wf-raw-filter=ip and (ip.DstAddr==203.0.113.7 or ip.SrcAddr==203.0.113.7)'\n") && config.EndsWith("\n" + tls.Args.Trim() + "\n"), "The configuration file: " + config);
        var from = ZapretTarget.For("203.0.113.7", ProxyProfile.Parse(QuicServerLink));
        Check(from.Quic && from.Port == 5443 && from.Address == "203.0.113.7" && !ZapretTarget.For("203.0.113.7", ProxyProfile.Parse(TcpServerLink)).Quic && ZapretTarget.For("::1", ProxyProfile.Parse(TcpServerLink)).Port == 443,
            "The target takes the port and the transport from the link and the address from the program");

        // стратегия WARP собирается как раньше
        zapret.ExtraAddresses = new string[0];
        var warp = zapret.BuildArgs(tls, true);
        Check(warp.Contains("--wf-tcp-out=1-65535") && RawFilter(warp).Contains("162.159.192.0") && zapret.BuildArgs(tls, false).Contains("--wf-tcp-out=443"), "The arguments for WARP are unchanged");
    }

    /// <summary>Фильтр WinDivert, который winws2 составит для конфигурации (--wf-save: ничего не перехватывает и прав администратора не требует).</summary>
    static string SavedFilter(Zapret zapret, string config, string name)
    {
        File.WriteAllText(Path.Combine(zapret.Dir, name + ".cfg"), config, new System.Text.UTF8Encoding(false));
        File.WriteAllText(Path.Combine(_artifacts, name + ".cfg"), config, new System.Text.UTF8Encoding(false));
        string output = Path.Combine(zapret.Dir, name + ".filter");
        File.Delete(output);
        var psi = new System.Diagnostics.ProcessStartInfo(zapret.Exe, "@" + name + ".cfg --wf-save=" + name + ".filter") { WorkingDirectory = zapret.Dir };
        psi.EnvironmentVariables["__COMPAT_LAYER"] = "RunAsInvoker";
        var lost = new List<TestProcessResult>();
        var run = RunUntilLoaded(() => RunTestProcess(psi, 30000), lost);
        Check(run.StartError == null && !run.TimedOut && run.OutputComplete && run.Code == 0 && File.Exists(output), name + ": winws2 did not save the filter.\n" + run.Describe());
        string filter = File.ReadAllText(output);
        File.WriteAllText(Path.Combine(_artifacts, name + ".filter"), filter, new System.Text.UTF8Encoding(false));
        return filter;
    }

    static void TestServerTargetFilters() => WithEmbeddedZapret(zapret =>
    {
        if (!Environment.Is64BitProcess) throw new TestSkippedException("The 64-bit WinDivert.dll cannot be loaded into a 32-bit test process");
        var tls = StrategyCatalog.BuiltInStrategies.First(s => s.Transport == WarpTransport.MasqueH2);
        var quicStrategy = StrategyCatalog.BuiltInStrategies.First(s => s.Transport == WarpTransport.MasqueH3);
        string dll = Path.Combine(zapret.Dir, "WinDivert.dll");
        const string LanBlock = "ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255";

        var cases = new[]
        {
            (Name: "tcp4", Strategy: tls, Target: new ZapretTarget { Address = "203.0.113.7", Port = 8443 }),
            (Name: "tcp6", Strategy: tls, Target: new ZapretTarget { Address = "2001:db8::7", Port = 8443 }),
            (Name: "quic4", Strategy: quicStrategy, Target: new ZapretTarget { Address = "203.0.113.7", Port = 5443, Quic = true }),
            (Name: "quic6", Strategy: quicStrategy, Target: new ZapretTarget { Address = "2001:db8::7", Port = 5443, Quic = true }),
            (Name: "lan4", Strategy: tls, Target: new ZapretTarget { Address = "192.168.1.5", Port = 443 }),
            (Name: "lan6", Strategy: tls, Target: new ZapretTarget { Address = "fd12::5", Port = 443 }),
            (Name: "loopback", Strategy: tls, Target: new ZapretTarget { Address = "127.0.0.1", Port = 443 }),
        };
        foreach (var c in cases)
        {
            string filter = SavedFilter(zapret, zapret.BuildConfig(c.Strategy, c.Target), c.Name);
            var ip = c.Target.Ip;
            string family = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "ipv6" : "ip";
            Check(filter.Contains(family + " and (" + family + ".DstAddr==" + ip + " or " + family + ".SrcAddr==" + ip + ")"), c.Name + ": the filter names the address of the server");
            Check(c.Target.Quic ? filter.Contains("udp.DstPort==" + c.Target.Port) && !filter.Contains("tcp.DstPort")
                                : filter.Contains("tcp.DstPort == " + c.Target.Port) && filter.Contains("tcp.SrcPort == " + c.Target.Port) && !filter.Contains("udp.DstPort"),
                c.Name + ": the filter names the port of the server and the right protocol");
            Check(!filter.Contains("162.159.") && !filter.Contains("188.114.") && !filter.Contains("2606:4700"), c.Name + ": nothing of the WARP ranges");
            Check(filter.Contains(LanBlock) == (c.Name != "lan4" && c.Name != "lan6"), c.Name + ": the exclusion of the local network is switched off only for a server in it");
            Check(filter.Contains("!loopback") == (c.Name != "loopback"), c.Name + ": the exclusion of loopback is switched off only for a server on this computer");
            Check(WinDivertSyntaxError(dll, filter) == null, c.Name + ": WinDivert must accept the filter -> " + WinDivertSyntaxError(dll, filter) + "\n" + filter);
        }
    });

    static void TestServerStrategyDryRun(Strategy strategy, bool ipv6) => WithEmbeddedZapret(zapret =>
    {
        var target = new ZapretTarget { Address = ipv6 ? "2001:db8::7" : "203.0.113.7", Port = strategy.Transport == WarpTransport.MasqueH3 ? 5443 : 8443, Quic = strategy.Transport == WarpTransport.MasqueH3 };
        var run = DryRun(zapret, zapret.BuildConfig(strategy, target));
        Check(run.StartError == null && !run.TimedOut && run.OutputComplete && run.Code == 0 && run.Stdout.Contains("command line parameters verified"),
            $"{strategy.Id}, ipv6={ipv6}: winws2 did not verify the configuration.\n" + File.ReadAllText(Path.Combine(_artifacts, "winws2.txt")));
    });

    /// <summary>
    /// Без zapret2 режим сервера не начинается: подготовка распаковывает вшитый zapret2. Ничего не запускается (подготовка не запускает
    /// winws2), так что WinDivert не открывается.
    /// </summary>
    static async Task TestServerZapretPrepareAsync()
    {
        var embedded = typeof(Zapret).GetField("_embeddedVersion", PrivateStatic);
        embedded.SetValue(null, null);
        try
        {
            if (Zapret.EmbeddedVersion == null) throw new TestSkippedException("Zarp was built without embedded zapret2; run tools/fetch-zapret.ps1 before building.");
            var engine = NewEngine();
            SetPrivate(engine, "Proxy", new FakeProxy(Path.Combine(engine.DataDir, "fake-singbox")));
            SetPrivate(engine, "FindForeignVpns", (Func<List<string>>)(() => new List<string>()));
            engine.Config.UseProxy = true;
            engine.Config.ProxyUri = TestLink;
            engine.ReloadStrategies();
            Check(!engine.Zapret.Installed && engine.Strategies.Count > 0, "Setup: zapret2 is not unpacked yet");
            var prepare = typeof(Engine).GetMethod("PrepareProxyAsync", PrivateInstance);
            bool ready = await (Task<bool>)prepare.Invoke(engine, new object[] { CancellationToken.None, true });
            Check(ready && engine.Zapret.Installed && !engine.Zapret.Running, "Preparing for a server unpacks the embedded zapret2 and starts nothing");
        }
        finally { embedded.SetValue(null, ""); }
    }

    /// <summary>Запуск winws2 для сервера движком: подставная программа, но настоящие файл конфигурации, поиск процесса по пути и остановка.</summary>
    static async Task TestServerZapretLifecycleAsync()
    {
        var engine = NewEngine();
        StubFiles(engine.Zapret.Dir, "v1.0", SleepingWinws());
        var zapret = engine.Zapret;
        SetPrivate(zapret, "SettleDelayMs", 10);
        var s = StrategyCatalog.BuiltInStrategies.First(x => x.Transport == WarpTransport.MasqueH2);
        var server = ProxyProfile.Parse(TcpServerLink);
        var other = ProxyProfile.Parse("trojan://secret@other.example:8443");
        try
        {
            Check(!zapret.Running && zapret.RunningStrategyArgs() == null, "Nothing runs at first");
            Check(await zapret.StartAsync(s, ZapretTarget.For("203.0.113.7", server)) == null && zapret.Running, "winws2 starts for a server");
            string config = File.ReadAllText(Path.Combine(zapret.Dir, "zarp.cfg"));
            Check(config.Contains("'--wf-tcp-out=443'") && config.Contains("ip.DstAddr==203.0.113.7") && zapret.RunningStrategyArgs() == s.Args.Trim(), "It runs with the file of this server and says which strategy it has");

            // другой сервер заменяет прежний перехват
            Check(await zapret.StartAsync(s, ZapretTarget.For("198.51.100.9", other)) == null && zapret.Running, "It restarts for another server");
            config = File.ReadAllText(Path.Combine(zapret.Dir, "zarp.cfg"));
            Check(config.Contains("'--wf-tcp-out=8443'") && config.Contains("ip.DstAddr==198.51.100.9") && !config.Contains("203.0.113.7"), "and the old interception is gone: " + config);

            // неверный адрес - это отказ запуска с понятным текстом, а не исключение; прежний winws2 остановлен
            var failure = await zapret.StartAsync(s, new ZapretTarget { Address = "not-an-address", Port = 443 });
            Check(failure != null && failure.Key == "err.winwsStart" && !zapret.Running, "A wrong address is a failed start, and nothing keeps running: " + failure);

            // стратегия без zapret2 ничего не запускает
            Check(await zapret.StartAsync(PlainStrategy("plain"), ZapretTarget.For("203.0.113.7", server)) == null && !zapret.Running, "A strategy without zapret2 starts nothing");

            // остановка
            Check(await zapret.StartAsync(s, ZapretTarget.For("203.0.113.7", server)) == null && zapret.Running, "Setup: running");
            zapret.Stop();
            Check(!zapret.Running && zapret.RunningStrategyArgs() == null, "Stop switches it off");

            // отмена посреди запуска не оставляет winws2
            using (var cancelled = new System.Threading.CancellationTokenSource())
            {
                cancelled.Cancel();
                Check(await Catch(async () => await zapret.StartAsync(s, ZapretTarget.For("203.0.113.7", server), cancelled.Token)) is OperationCanceledException && !zapret.Running, "A cancelled start leaves nothing running");
            }
        }
        finally { zapret.Stop(); }
    }
}
