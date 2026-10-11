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

// VLESS поверх XHTTP: разбор ссылок, конфигурации sing-box и Xray, настоящие серверы Xray на localhost. sing-box такой транспорт
// не умеет, поэтому перед ним работает мост Xray. Ни виртуальный адаптер, ни настоящие WARP и WinDivert не запускаются.
static partial class Program
{
    const string XhttpBase = "vless://" + TestUuid + "@x.example:443?";
    static readonly string HexPin = new string('a', 64);

    /// <summary>Исходящее подключение Xray из ссылки: как оно попадёт в конфигурацию (массивы - object[]).</summary>
    static Dictionary<string, object> XrayOutbound(string link, string address = "203.0.113.5") =>
        JsonObject(new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(ProxyProfile.Parse(link).BuildXrayOutbound(address)));

    static Dictionary<string, object> XrayStream(Dictionary<string, object> outbound) => Obj(outbound["streamSettings"]);

    static void TestXhttpProfiles()
    {
        // Reality: всё, что кладут в ссылку обычные панели
        string link = XhttpBase + "type=xhttp&encryption=none&security=reality&pbk=" + TestRealityKey + "&sid=0123abcd&sni=www.example.org&fp=chrome&spx=%2F&path=%2Fxh&host=front.example" +
                      "&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D#My%20server";
        var reality = ProxyProfile.Parse(link);
        Check(reality.UsesXray && reality.Protocol == ProxyProtocol.Vless && reality.Title == "VLESS" && reality.Endpoint == "x.example:443", "An XHTTP link is a VLESS server that goes through the Xray bridge");
        var strategy = reality.ToStrategy();
        Check(strategy.IsProxy && !strategy.UsesZapret && strategy.Name == "VLESS: x.example:443" && !(strategy.Id + strategy.Name).Contains(TestUuid), "The strategy never carries the UUID");
        var o = XrayOutbound(link);
        var node = Obj(Arr(Obj(o["settings"])["vnext"]).Single());
        var user = Obj(Arr(node["users"]).Single());
        Check((string)o["tag"] == "server" && (string)o["protocol"] == "vless" && (string)node["address"] == "203.0.113.5" && (int)node["port"] == 443, "VLESS goes to the resolved address");
        Check((string)user["id"] == TestUuid && (string)user["encryption"] == "none" && (string)user["flow"] == "", "VLESS user without encryption and flow");
        var stream = XrayStream(o);
        var xhttp = Obj(stream["xhttpSettings"]);
        Check((string)stream["network"] == "xhttp" && (string)stream["security"] == "reality" && !stream.ContainsKey("tlsSettings"), "XHTTP over Reality");
        Check((string)xhttp["path"] == "/xh" && (string)xhttp["mode"] == "packet-up" && (string)xhttp["host"] == "front.example", "XHTTP path, mode and host");
        Check((string)Obj(xhttp["extra"])["xPaddingBytes"] == "100-1000" && (string)Obj(Obj(xhttp["extra"])["xmux"])["maxConcurrency"] == "16-32", "The extra settings reach Xray as they are");
        var r = Obj(stream["realitySettings"]);
        Check((string)r["serverName"] == "www.example.org" && (string)r["fingerprint"] == "chrome" && (string)r["publicKey"] == TestRealityKey &&
              (string)r["shortId"] == "0123abcd" && (string)r["spiderX"] == "/" && !r.ContainsKey("mldsa65Verify"), "Reality parameters");
        Check(ProxyProfile.Parse(link.Replace("#My%20server", "#other")).Id == reality.Id && ProxyProfile.Parse(link.Replace("packet-up", "stream-up")).Id != reality.Id, "The label is not part of the identity, the mode is");

        // Reality без отпечатка и spx: отпечаток chrome по умолчанию, обходной путь не задаётся
        r = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=reality&pbk=" + TestRealityKey + "&sni=www.example.org"))["realitySettings"]);
        Check((string)r["fingerprint"] == "chrome" && (string)r["shortId"] == "" && !r.ContainsKey("spiderX"), "Reality defaults to the chrome fingerprint and sets no spiderX");
        // открытый ключ ML-DSA-65 для проверки сервера
        string mldsa = new string('A', 2603);
        r = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=reality&pbk=" + TestRealityKey + "&sni=a.example&pqv=" + mldsa))["realitySettings"]);
        Check((string)r["mldsa65Verify"] == mldsa, "The ML-DSA-65 key is passed on");

        // TLS: имя, ALPN, отпечаток, закрепление сертификата (в Xray - одна строка из hex через запятую, двоеточия и регистр не важны)
        var tlsOutbound = XrayOutbound(XhttpBase + "type=xhttp&security=tls&sni=s.example&alpn=h2,%20http/1.1&fp=firefox&pcs=" + HexPin.ToUpperInvariant() + "&vcn=s.example,*.t.example&mode=stream-up&path=%2Fp");
        var tls = Obj(XrayStream(tlsOutbound)["tlsSettings"]);
        xhttp = Obj(XrayStream(tlsOutbound)["xhttpSettings"]);
        Check((string)tls["serverName"] == "s.example" && Arr(tls["alpn"]).Cast<string>().SequenceEqual(new[] { "h2", "http/1.1" }) && (string)tls["fingerprint"] == "firefox", "TLS name, ALPN and fingerprint");
        Check((string)tls["pinnedPeerCertSha256"] == HexPin && (string)tls["verifyPeerCertByName"] == "s.example,*.t.example", "Certificate pinning goes to Xray as strings");
        Check((string)xhttp["mode"] == "stream-up" && (string)xhttp["path"] == "/p" && !xhttp.ContainsKey("host") && !xhttp.ContainsKey("extra"), "Without host and extra only path and mode are set");
        string colons = string.Join(":", Enumerable.Repeat("AB", 32));
        tls = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=tls&pcs=" + colons + "," + HexPin))["tlsSettings"]);
        Check((string)tls["pinnedPeerCertSha256"] == string.Concat(Enumerable.Repeat("ab", 32)) + "," + HexPin && (string)tls["serverName"] == "x.example" && !tls.ContainsKey("fingerprint") && !tls.ContainsKey("alpn"),
            "Several pins, the OpenSSL form with colons; the TLS name defaults to the server name");

        // без TLS: имя сервера уходит в Host запроса (без него там был бы IP-адрес), IP-адрес вместо имени - нет
        xhttp = Obj(XrayStream(XrayOutbound(XhttpBase.Replace(":443", ":80") + "type=xhttp&path=%2Fa"))["xhttpSettings"]);
        Check((string)xhttp["host"] == "x.example" && (string)xhttp["path"] == "/a" && (string)xhttp["mode"] == "auto", "Without TLS the Host of the request is the server name");
        xhttp = Obj(XrayStream(XrayOutbound("vless://" + TestUuid + "@203.0.113.7:80?type=xhttp"))["xhttpSettings"]);
        Check(!xhttp.ContainsKey("host") && (string)xhttp["path"] == "/", "An address instead of a name is not sent as Host; the path defaults to a slash");
        Check((string)Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&path="))["xhttpSettings"])["path"] == "/", "An empty path is a slash too");
        xhttp = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&host=h.example"))["xhttpSettings"]);
        Check((string)xhttp["host"] == "h.example" && (string)Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp"))["xhttpSettings"])["host"] == "x.example", "A host from the link wins");
        Check(XrayStream(XrayOutbound(XhttpBase + "type=xhttp"))["security"].Equals("none") && !XrayStream(XrayOutbound(XhttpBase + "type=xhttp")).ContainsKey("tlsSettings"), "No security by default, as for the other VLESS links");

        // пустые значения - то же, что отсутствие; пустой extra ничего не добавляет
        var blank = ProxyProfile.Parse(XhttpBase + "type=xhttp&security=tls&mode=&extra=&host=&spx=&pcs=&vcn=&pqv=");
        xhttp = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=tls&mode=&extra=&host=&spx=&pcs=&vcn=&pqv="))["xhttpSettings"]);
        Check(blank.UsesXray && (string)xhttp["mode"] == "auto" && !xhttp.ContainsKey("extra") && !xhttp.ContainsKey("host"), "Empty values are the same as no values");
        xhttp = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&extra=%7B%7D"))["xhttpSettings"]);
        Check(!xhttp.ContainsKey("extra"), "An empty extra object adds nothing");
        // extra сохраняет типы: числа, логические значения, вложенные объекты и массивы
        var extra = Obj(Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&extra=" + Uri.EscapeDataString("{\"a\":1,\"b\":[1,2],\"c\":{\"d\":true},\"e\":null,\"f\":1.5,\"g\":\"text\"}")))["xhttpSettings"])["extra"]);
        Check((int)extra["a"] == 1 && Arr(extra["b"]).Length == 2 && (bool)Obj(extra["c"])["d"] && extra["e"] == null && Convert.ToDecimal(extra["f"]) == 1.5m && (string)extra["g"] == "text", "extra keeps numbers, flags, arrays and nested objects");

        // допустимые режимы
        foreach (var mode in new[] { "auto", "packet-up", "stream-up", "stream-one" })
            Check((string)Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&mode=" + mode))["xhttpSettings"])["mode"] == mode, "Mode " + mode + " is accepted");

        // XHTTP идёт только через мост; остальные ссылки Xray не касаются
        Check(!ProxyProfile.Parse("trojan://s@x.example:443").UsesXray && !ProxyProfile.Parse(XhttpBase + "type=ws&security=tls").UsesXray && !ProxyProfile.Parse(XhttpBase + "security=tls").UsesXray, "Only XHTTP uses the bridge");
        Check(Catch(() => ProxyProfile.Parse(link).BuildOutbound()) is InvalidOperationException, "sing-box is never given an XHTTP outbound");
        Check(Catch(() => ProxyProfile.Parse("trojan://s@x.example:443").BuildXrayOutbound()) is InvalidOperationException &&
              Catch(() => ProxyProfile.Parse(XhttpBase + "security=tls").BuildXrayOutbound()) is InvalidOperationException, "Xray is never given a link that is not XHTTP");
        var bridge = ProxyProfile.BuildBridgeOutbound(18081, "bridge", "secret-bridge");
        Check((string)bridge["type"] == "socks" && (string)bridge["tag"] == "proxy" && (string)bridge["server"] == "127.0.0.1" && (int)bridge["server_port"] == 18081 &&
              (string)bridge["version"] == "5" && (string)bridge["username"] == "bridge" && (string)bridge["password"] == "secret-bridge", "sing-box reaches the bridge over SOCKS5 with a password on loopback");

        // что отвергается: причина в Reason, в тексте ошибки нет ни ссылки, ни значений
        string key = "&pbk=" + TestRealityKey;
        var refused = new[]
        {
            ("type=xhttp&mode=bogus", "format"), ("type=xhttp&mode=AUTO", "format"),
            ("type=xhttp&extra=nope", "extra"), ("type=xhttp&extra=%5B1%5D", "extra"), ("type=xhttp&extra=%22text%22", "extra"), ("type=xhttp&extra=%7B%22a%22", "extra"),
            ("type=xhttp&security=tls&allowInsecure=1", "insecure"), ("type=xhttp&security=tls&insecure=true", "insecure"), ("type=xhttp&allowInsecure=1", "insecure"),
            ("type=xhttp&security=tls&flow=xtls-rprx-vision", "format"),
            ("type=ws&mode=auto", "param:mode"), ("mode=auto", "param:mode"), ("type=grpc&extra=%7B%7D", "param:extra"), ("extra=%7B%7D", "param:extra"),
            ("type=xhttp&security=tls&spx=%2F", "param:spx"), ("type=xhttp&spx=%2F", "param:spx"), ("security=reality" + key + "&spx=%2F", "param:spx"),
            ("type=xhttp&security=reality" + key + "&spx=abc", "format"), ("type=xhttp&security=reality" + key + "&pqv=short", "format"),
            ("type=xhttp&security=tls&pqv=" + new string('A', 2603), "param:pqv"),
            ("type=xhttp&security=reality" + key + "&pcs=" + HexPin, "param:pcs"), ("type=xhttp&pcs=" + HexPin, "param:pcs"), ("security=tls&pcs=" + HexPin, "param:pcs"),
            ("type=xhttp&security=reality" + key + "&vcn=a.example", "param:vcn"),
            ("type=xhttp&security=tls&pcs=" + new string('a', 63), "format"), ("type=xhttp&security=tls&pcs=" + new string('g', 64), "format"), ("type=xhttp&security=tls&pcs=,", "format"),
            ("type=xhttp&security=tls&pcs=" + string.Join(",", Enumerable.Repeat(HexPin, 9)), "format"),
            ("type=xhttp&security=tls&vcn=bad%20name", "format"), ("type=xhttp&security=tls&vcn=-x", "format"), ("type=xhttp&security=tls&vcn=,", "format"),
            ("type=xhttp&security=tls&vcn=" + string.Join(",", Enumerable.Repeat("a.example", 9)), "format"),
            ("type=xhttp&fm=%7B%7D", "param:fm"), ("type=xhttp&ech=abc", "param:ech"),
            ("type=splithttp", "transport:splithttp"), ("type=xhttp&security=xtls", "security:xtls"), ("type=kcp", "transport:kcp"),
        };
        foreach (var (query, reason) in refused)
        {
            string bad = XhttpBase + query;
            var failure = Catch(() => ProxyProfile.Parse(bad)) as ProxyLinkException;
            Check(failure != null && failure.Message == "proxy.invalid" && failure.Reason == reason, "Must be refused as '" + reason + "': " + query + " -> " + (failure == null ? "accepted" : failure.Reason));
            Check(!ProxyProfile.TryParse(bad, out _), "TryParse must refuse: " + query);
            var why = ProxyProfile.Explain(bad);
            Check(why != null && !why.ToString().Contains(TestUuid) && !why.ToString().Contains(HexPin) && !why.ToString().Contains(TestRealityKey), "The explanation holds no secrets: " + query);
        }
        // трояну и Hysteria2 XHTTP недоступен: такой транспорт только у VLESS
        foreach (var other in new[] { "trojan://secret@x.example:443?type=xhttp", "hy2://secret@x.example:443?type=xhttp" })
        {
            var failure = Catch(() => ProxyProfile.Parse(other)) as ProxyLinkException;
            Check(failure != null && failure.Reason == "transport:xhttp", "XHTTP is only for VLESS: " + other.Replace("secret", "***"));
        }
        // сообщения для окна
        Check(ProxyProfile.Explain(XhttpBase + "type=xhttp&extra=nope").Key == "proxy.extra" && ProxyProfile.Explain(XhttpBase + "type=xhttp&allowInsecure=1").Key == "proxy.insecure", "The window names a bad extra and a skipped certificate check");
        var param = ProxyProfile.Explain(XhttpBase + "type=xhttp&fm=1");
        Check(param.Key == "proxy.param" && (string)param.Args[0] == "fm", "An unsupported parameter of an XHTTP link is named");
        Check(ProxyProfile.Explain(XhttpBase + "type=xhttp&security=tls&allowInsecure=0&insecure=false") == null, "Explicitly keeping the certificate check is fine");
        Check(ProxyProfile.Explain(link) == null, "A good XHTTP link has no explanation");
        Check(Regex.IsMatch(ProxyProfile.Parse(link).Id, "^proxy-[0-9a-f]{24}$"), "The identity of an XHTTP link has the same form as the others");
    }

    static ProxySession XhttpSession(ProxyProfile profile, bool tun) => new ProxySession
    {
        Profile = profile, Address = "203.0.113.5", Port = 18080, User = "zarp", Password = "pw", Tun = tun,
        XrayPort = 18081, XrayUser = "bridge", XrayPassword = "secret-bridge", XrayPath = @"C:\Users\x\AppData\Local\Zarp\xray\xray.exe",
    };

    static void TestXrayConfig()
    {
        var profile = ProxyProfile.Parse(XhttpBase + "type=xhttp&security=reality&pbk=" + TestRealityKey + "&sid=0123abcd&sni=www.example.org&mode=stream-up");

        // конфигурация Xray: только мост и один выход, никакой маршрутизации
        var cfg = JsonObject(XrayConfig.Build(XhttpSession(profile, false)));
        Check(cfg.Keys.OrderBy(k => k).SequenceEqual(new[] { "inbounds", "log", "outbounds" }), "Xray gets no routing, DNS or policy of its own: " + string.Join(",", cfg.Keys));
        var log = Obj(cfg["log"]);
        Check((string)log["access"] == "none", "The access log (it lists the places the user visits) is off");
        Check((string)log["loglevel"] == "info" && (string)Obj(JsonObject(XrayConfig.Build(XhttpSession(profile, true)))["log"])["loglevel"] == "warning",
            "Failures are logged in detail only while the server is checked without the adapter, never while the user's traffic flows");
        var inbound = Obj(Arr(cfg["inbounds"]).Single());
        var settings = Obj(inbound["settings"]);
        var account = Obj(Arr(settings["users"]).Single());
        Check((string)inbound["listen"] == "127.0.0.1" && (int)inbound["port"] == 18081 && (string)inbound["protocol"] == "socks" && (string)inbound["tag"] == "bridge", "The bridge listens on loopback only");
        Check((string)settings["auth"] == "password" && (string)account["user"] == "bridge" && (string)account["pass"] == "secret-bridge" && (bool)settings["udp"] && (string)settings["ip"] == "127.0.0.1",
            "The bridge asks for a password and relays UDP through loopback");
        var outbound = Obj(Arr(cfg["outbounds"]).Single());
        Check((string)outbound["protocol"] == "vless" && (string)Obj(Arr(Obj(outbound["settings"])["vnext"]).Single())["address"] == "203.0.113.5" &&
              (string)Obj(outbound["streamSettings"])["network"] == "xhttp", "The only outbound is the server, dialled by its resolved address");
        Check(Catch(() => XrayConfig.Build(XhttpSession(ProxyProfile.Parse("trojan://s@x.example:443"), false))) is InvalidOperationException, "A server that is not XHTTP has no Xray configuration");
        var noLogin = XhttpSession(profile, false);
        noLogin.XrayPassword = null;
        Check(Catch(() => XrayConfig.Build(noLogin)) is InvalidOperationException && Catch(() => ProxyConfig.Build(noLogin)) is InvalidOperationException, "A bridge without a login is never configured");
        noLogin = XhttpSession(profile, false);
        noLogin.XrayPort = 0;
        Check(Catch(() => XrayConfig.Build(noLogin)) is InvalidOperationException && Catch(() => ProxyConfig.Build(noLogin)) is InvalidOperationException, "A bridge without a port is never configured");

        // sing-box: пустая проверка - только проверочный вход и выход в мост; ни UUID, ни адреса сервера он не знает
        string probe = ProxyConfig.Build(XhttpSession(profile, false));
        var sing = JsonObject(probe);
        var bridge = Obj(Arr(sing["outbounds"])[0]);
        Check((string)bridge["type"] == "socks" && (string)bridge["tag"] == "proxy" && (string)bridge["server"] == "127.0.0.1" && (int)bridge["server_port"] == 18081 &&
              (string)bridge["username"] == "bridge" && (string)bridge["password"] == "secret-bridge" && (string)bridge["version"] == "5", "sing-box sends everything to the bridge");
        Check(!probe.Contains(TestUuid) && !probe.Contains("203.0.113.5") && !probe.Contains(TestRealityKey) && !probe.Contains("0123abcd"), "sing-box knows nothing about the server itself");
        Check(Arr(Obj(sing["route"])["rules"]).Length == 1 && !probe.Contains("route_exclude_address") && !probe.Contains("xray.exe"), "A check without the adapter needs no routing around the bridge");

        // с адаптером: Xray ходит к серверу мимо адаптера (правило по пути программы и исключённый маршрут)
        var tunCfg = JsonObject(ProxyConfig.Build(XhttpSession(profile, true)));
        var tun = Obj(Arr(tunCfg["inbounds"]).First());
        Check(Arr(tun["route_exclude_address"]).Cast<string>().SequenceEqual(new[] { "203.0.113.5/32" }), "The address of the server is taken out of the routes of the adapter");
        var rules = Arr(Obj(tunCfg["route"])["rules"]).Select(Obj).ToList();
        Check(((object[])rules[0]["inbound"])[0].Equals("probe-in") && rules.Count == 4, "The probe still goes first: " + rules.Count + " rules");
        Check(Arr(rules[1]["process_path_regex"]).Single().Equals(ProxyConfig.AppPattern(@"C:\Users\x\AppData\Local\Zarp\xray\xray.exe")) && (string)rules[1]["outbound"] == "direct" && !rules[1].ContainsKey("invert"),
            "Traffic of xray.exe itself goes direct, right after the probe");
        Check((string)Obj(Arr(tunCfg["outbounds"])[0])["type"] == "socks" && !ProxyConfig.Build(XhttpSession(profile, true)).Contains(TestUuid), "The adapter session does not carry the UUID either");

        var v6 = XhttpSession(profile, true);
        v6.Address = "2001:db8::5";
        tun = Obj(Arr(JsonObject(ProxyConfig.Build(v6))["inbounds"]).First());
        Check(Arr(tun["route_exclude_address"]).Cast<string>().SequenceEqual(new[] { "2001:db8::5/128" }), "An IPv6 address is excluded as a /128");
        var unresolved = XhttpSession(profile, true);
        unresolved.Address = null; // имя вместо адреса: исключать нечего, Engine всегда передаёт разрешённый адрес
        Check(!ProxyConfig.Build(unresolved).Contains("route_exclude_address"), "Nothing is excluded for an unresolved name");
        var noPath = XhttpSession(profile, true);
        noPath.XrayPath = null;
        Check(Arr(Obj(JsonObject(ProxyConfig.Build(noPath))["route"])["rules"]).Length == 3, "Without a path of xray.exe there is no rule for it");

        // правило для xray.exe стоит перед выбором программ и пользовательскими правилами: что бы они ни говорили, мост не должен вернуться в адаптер
        var full = XhttpSession(profile, true);
        full.AppPaths = new List<string> { @"C:\Tools\app.exe" };
        full.OwnPath = @"C:\Zarp\Zarp.exe";
        full.Rules = new List<object> { new Dictionary<string, object> { ["ip_cidr"] = new List<string> { "0.0.0.0/0" }, ["action"] = "route", ["outbound"] = "proxy" } };
        rules = Arr(Obj(JsonObject(ProxyConfig.Build(full))["route"])["rules"]).Select(Obj).ToList();
        Check(rules.Count > 5 && ((object[])rules[0]["inbound"])[0].Equals("probe-in") && Arr(rules[1]["process_path_regex"]).Single().Equals(ProxyConfig.AppPattern(@"C:\Users\x\AppData\Local\Zarp\xray\xray.exe")) &&
              (string)rules[1]["outbound"] == "direct" && Arr(rules[2]["process_path_regex"]).Single().Equals(ProxyConfig.AppPattern(@"C:\Zarp\Zarp.exe")),
            "With programs chosen and rules set, xray.exe is still first after the probe");
        // для проверки правил на настоящем sing-box без адаптера (RulesOnProbe) правило тоже есть
        var onProbe = XhttpSession(profile, false);
        onProbe.RulesOnProbe = true;
        Check(Arr(Obj(JsonObject(ProxyConfig.Build(onProbe))["route"])["rules"]).Select(Obj)
                  .Any(rule => rule.ContainsKey("process_path_regex") && Arr(rule["process_path_regex"]).Single().Equals(ProxyConfig.AppPattern(@"C:\Users\x\AppData\Local\Zarp\xray\xray.exe"))),
            "The rule is also built when the rules are tried on the probe");

        // другие серверы остаются как были
        var trojan = TestSession(ProxyProfile.Parse("trojan://secret@proxy.example:443"), true);
        string trojanConfig = ProxyConfig.Build(trojan);
        Check(!trojanConfig.Contains("route_exclude_address") && (string)Obj(Arr(JsonObject(trojanConfig)["outbounds"])[0])["type"] == "trojan" && !trojanConfig.Contains("xray"),
            "A server that is not XHTTP gets no bridge and no extra routes");

        // сессия: порты и пароли моста
        var runtime = new ProxyRuntime(new SingBox(Path.Combine(_data, "ns-box")), new Xray(Path.Combine(_data, "ns-xray")));
        var first = runtime.NewSession(profile);
        var second = runtime.NewSession(profile);
        Check(first.XrayPort > 0 && first.XrayPort != first.Port && first.XrayUser == "zarp" && first.XrayPassword.Length >= 32 && first.XrayPassword != first.Password &&
              first.XrayPath == Path.GetFullPath(Path.Combine(_data, "ns-xray", "xray.exe")), "A session gets its own port and password for the bridge");
        Check(first.XrayPassword != second.XrayPassword && first.Password != second.Password, "Every session has new passwords");
        var plain = runtime.NewSession(ProxyProfile.Parse("trojan://secret@proxy.example:443"));
        Check(plain.XrayPort == 0 && plain.XrayUser == null && plain.XrayPassword == null && plain.XrayPath == null, "Other servers get no bridge");
        Check(new ProxyRuntime(new SingBox(Path.Combine(_data, "ns-box"))).NewSession(profile).XrayPath == null, "Without Xray there is no path to its program");
    }

    /// <summary>Список ECH нужной длины: два байта длины и тело, как у настоящего ECHConfigList.</summary>
    static string FakeEch(int body = 100, bool urlSafe = false)
    {
        var bytes = new byte[body + 2];
        bytes[0] = (byte)(body >> 8);
        bytes[1] = (byte)body;
        for (int i = 2; i < bytes.Length; i++) bytes[i] = (byte)(i * 37 + 11);
        string text = Convert.ToBase64String(bytes);
        return urlSafe ? text.TrimEnd('=').Replace('+', '-').Replace('/', '_') : text;
    }

    /// <summary>
    /// Параметры ссылок, которые добавляют панели вроде 3x-ui: ech (зашифрованный ClientHello), x_padding_bytes рядом с extra и
    /// подсказка support-x25519mlkem768 для Reality; а также подпись сервера после #.
    /// </summary>
    static void TestLinkExtras()
    {
        // ссылка того же вида, что у панели: Reality поверх XHTTP со всем, что панель кладёт в неё
        string extra = Uri.EscapeDataString("{\"sessionKey\":\"Session-ID\",\"sessionPlacement\":\"header\",\"xPaddingBytes\":\"167-1300\"}");
        string panel = XhttpBase + "encryption=none&extra=" + extra + "&fp=firefox&host=www.example.org&mode=auto&path=%2Fsample%2Fpath&pbk=" + TestRealityKey +
                       "&security=reality&sid=0a1b2c3d&sni=www.example.org&spx=%2Fa1b2c3d4e5f6&support-x25519mlkem768=true&type=xhttp&x_padding_bytes=167-1300#Main_one-client01";
        Check(ProxyProfile.Explain(panel) == null, "A link as a 3x-ui panel writes it is accepted: " + ProxyProfile.Explain(panel));
        var profile = ProxyProfile.Parse(panel);
        var o = XrayOutbound(panel);
        var xhttp = Obj(XrayStream(o)["xhttpSettings"]);
        var reality = Obj(XrayStream(o)["realitySettings"]);
        Check(profile.UsesXray && profile.Label == "Main_one-client01" && (string)xhttp["host"] == "www.example.org" && (string)xhttp["path"] == "/sample/path" && (string)xhttp["mode"] == "auto", "Host, path, mode and the label");
        Check((string)Obj(xhttp["extra"])["sessionPlacement"] == "header" && (string)Obj(xhttp["extra"])["xPaddingBytes"] == "167-1300" && !xhttp.ContainsKey("xPaddingBytes"), "extra goes to Xray as it is and the flat padding is not added next to it");
        Check((string)reality["shortId"] == "0a1b2c3d" && (string)reality["spiderX"] == "/a1b2c3d4e5f6" && (string)reality["fingerprint"] == "firefox" &&
              !JsonText(o).Contains("support-x25519mlkem768") && !JsonText(o).Contains("x_padding_bytes"), "Reality fields are used and the panel hints are not passed to Xray");

        // padding без extra: единственный источник, попадает в настройки XHTTP как xPaddingBytes
        xhttp = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&x_padding_bytes=100-1000"))["xhttpSettings"]);
        Check((string)xhttp["xPaddingBytes"] == "100-1000" && !xhttp.ContainsKey("extra"), "x_padding_bytes alone sets the padding");
        Check((string)Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&x_padding_bytes=500"))["xhttpSettings"])["xPaddingBytes"] == "500", "A single number is a padding too");
        Check((string)Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&x_padding_bytes=100-100"))["xhttpSettings"])["xPaddingBytes"] == "100-100", "A range of one size is a padding too");
        Check(!Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&x_padding_bytes="))["xhttpSettings"]).ContainsKey("xPaddingBytes"), "An empty padding is none");
        foreach (var bad in new[] { "0", "1000-100", "abc", "100-", "-5", "1,2", "9999999", "1-9999999", "01" })
        {
            var failure = Catch(() => ProxyProfile.Parse(XhttpBase + "type=xhttp&x_padding_bytes=" + bad)) as ProxyLinkException;
            Check(failure != null && failure.Reason == "format", "A padding of '" + bad + "' is refused: " + (failure?.Reason ?? "accepted"));
        }
        foreach (var query in new[] { "type=ws&x_padding_bytes=100", "x_padding_bytes=100" })
        {
            var failure = Catch(() => ProxyProfile.Parse(XhttpBase + query)) as ProxyLinkException;
            Check(failure != null && failure.Reason == "param:x_padding_bytes", "Padding is only for XHTTP: " + query);
        }

        // подсказка о гибридном обмене ключами: только Reality, значение логическое, ядрам ничего не добавляет
        string reality0 = XhttpBase + "security=reality&pbk=" + TestRealityKey + "&sni=www.example.org";
        foreach (var value in new[] { "true", "false", "1", "0" })
            Check(ProxyProfile.Explain(reality0 + "&support-x25519mlkem768=" + value) == null && ProxyProfile.Explain(reality0 + "&type=ws&support-x25519mlkem768=" + value) == null,
                "The ML-KEM hint " + value + " is accepted with Reality, over any transport");
        Check(JsonText(JObj(ProxyProfile.Parse(reality0 + "&support-x25519mlkem768=true").BuildOutbound())) == JsonText(JObj(ProxyProfile.Parse(reality0).BuildOutbound())), "The hint changes nothing in the sing-box outbound");
        Check(ProxyProfile.Parse(reality0 + "&support-x25519mlkem768=true").Id != ProxyProfile.Parse(reality0).Id, "But the link is another link (the identity follows the text)");
        foreach (var query in new[] { "security=tls&support-x25519mlkem768=true", "support-x25519mlkem768=true" })
        {
            var failure = Catch(() => ProxyProfile.Parse(XhttpBase + query)) as ProxyLinkException;
            Check(failure != null && failure.Reason == "param:support-x25519mlkem768", "The hint is only for Reality: " + query);
        }
        foreach (var value in new[] { "yes", "TRUE", "2" })
            Check(Catch(() => ProxyProfile.Parse(reality0 + "&support-x25519mlkem768=" + value)) is ProxyLinkException f && f.Reason == "format", "The hint takes a logical value: " + value);
        var named = ProxyProfile.Explain(XhttpBase + "type=xhttp&bogus=1");
        Check(named.Key == "proxy.param" && (string)named.Args[0] == "bogus", "Other parameters are still named and refused");

        // ECH: base64 (и вариант с - и _), длина в начале списка; нужен TLS
        string ech = FakeEch();
        string trojan = "trojan://secret@h.example:443?sni=h.example&ech=" + Uri.EscapeDataString(ech);
        Check(ProxyProfile.Explain(trojan) == null && ProxyProfile.Explain("trojan://secret@h.example:443?ech=" + FakeEch(urlSafe: true)) == null, "ECH is accepted as standard and as URL-safe base64");
        var tls = Obj(JObj(ProxyProfile.Parse(trojan).BuildOutbound())["tls"]);
        var echObject = Obj(tls["ech"]);
        var pem = Arr(echObject["config"]).Cast<string>().ToList();
        Check((bool)echObject["enabled"] && pem.First() == "-----BEGIN ECH CONFIGS-----" && pem.Last() == "-----END ECH CONFIGS-----" && pem.Skip(1).Take(pem.Count - 2).All(l => l.Length > 0 && l.Length <= 64) &&
              string.Concat(pem.Skip(1).Take(pem.Count - 2)) == ech, "sing-box gets the ECH list as PEM lines of at most 64 characters");
        var urlSafe = Obj(Obj(JObj(ProxyProfile.Parse("trojan://secret@h.example:443?ech=" + FakeEch(urlSafe: true)).BuildOutbound())["tls"])["ech"]);
        Check(string.Concat(Arr(urlSafe["config"]).Cast<string>().Skip(1).Take(Arr(urlSafe["config"]).Length - 2)) == ech, "The URL-safe form is turned into the standard one");
        // sing-box читает PEM, и ему нужен base64 с заполнением (=), которого в ссылке может не быть
        foreach (int body in new[] { 98, 99 })
        {
            string padded = FakeEch(body);
            Check(padded.EndsWith("="), "The test list needs padding: " + body);
            foreach (var form in new[] { FakeEch(body, urlSafe: true), padded.TrimEnd('=') })
            {
                var lines = Arr(Obj(Obj(JObj(ProxyProfile.Parse("trojan://secret@h.example:443?ech=" + form).BuildOutbound())["tls"])["ech"])["config"]).Cast<string>().ToList();
                Check(string.Concat(lines.Skip(1).Take(lines.Count - 2)) == padded, "A list written without padding is given to sing-box with padding: " + body);
            }
        }
        // у sing-box с ECH работает стандартный TLS: отпечаток uTLS не просим (у Hysteria2 его и так нет)
        var vless = Obj(JObj(ProxyProfile.Parse("vless://" + TestUuid + "@h.example:443?security=tls&fp=chrome&ech=" + Uri.EscapeDataString(ech)).BuildOutbound())["tls"]);
        Check(vless.ContainsKey("ech") && !vless.ContainsKey("utls"), "With ECH there is no uTLS fingerprint");
        Check(Obj(JObj(ProxyProfile.Parse("vless://" + TestUuid + "@h.example:443?security=tls&fp=chrome").BuildOutbound())["tls"]).ContainsKey("utls"), "Without ECH the fingerprint stays");
        var hy2 = Obj(JObj(ProxyProfile.Parse("hysteria2://secret@h.example:5443?alpn=h3&ech=" + Uri.EscapeDataString(ech) + "&fp=firefox&obfs=salamander&obfs-password=k&security=tls&sni=docs.example").BuildOutbound())["tls"]);
        Check((string)hy2["server_name"] == "docs.example" && hy2.ContainsKey("ech") && !hy2.ContainsKey("utls") && Arr(hy2["alpn"]).Single().Equals("h3"), "Hysteria2 takes ECH over QUIC");
        // у XHTTP конфигурация идёт в настройки TLS Xray
        var xrayTls = Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=tls&sni=s.example&ech=" + Uri.EscapeDataString(ech)))["tlsSettings"]);
        Check((string)xrayTls["echConfigList"] == ech && (string)xrayTls["serverName"] == "s.example", "Xray gets the ECH list in its TLS settings");
        Check(!Obj(XrayStream(XrayOutbound(XhttpBase + "type=xhttp&security=tls"))["tlsSettings"]).ContainsKey("echConfigList"), "No ECH, no list");
        // отказы
        string[] badEch = { "%%%", "AAAA", FakeEch(100).Substring(0, 120), "not base64!", new string('A', 5000), Convert.ToBase64String(new byte[] { 0, 9, 1, 2, 3, 4 }), Convert.ToBase64String(new byte[] { 0, 1 }) };
        foreach (var value in badEch)
        {
            var failure = Catch(() => ProxyProfile.Parse("trojan://secret@h.example:443?ech=" + Uri.EscapeDataString(value))) as ProxyLinkException;
            Check(failure != null && failure.Reason == "format", "A broken ECH list is refused: " + (value.Length > 30 ? value.Substring(0, 30) + "..." : value) + " -> " + (failure?.Reason ?? "accepted"));
        }
        // верхняя граница: 4096 знаков base64 - самый длинный список, длиннее отказ
        Check(ProxyProfile.Explain("trojan://secret@h.example:443?ech=" + Uri.EscapeDataString(FakeEch(3070))) == null, "An ECH list of 4096 characters is accepted");
        Check(Catch(() => ProxyProfile.Parse("trojan://secret@h.example:443?ech=" + Uri.EscapeDataString(FakeEch(3071)))) is ProxyLinkException tooLong && tooLong.Reason == "format", "A longer ECH list is refused");
        foreach (var query in new[] { "security=reality&pbk=" + TestRealityKey + "&ech=" + ech.Replace("+", "%2B"), "security=none&ech=" + ech.Replace("+", "%2B") })
        {
            var failure = Catch(() => ProxyProfile.Parse(XhttpBase + query)) as ProxyLinkException;
            Check(failure != null && failure.Reason == "param:ech", "ECH needs TLS: " + query.Substring(0, 14));
        }
        Check(ProxyProfile.Parse(trojan).Id != ProxyProfile.Parse(trojan.Replace(Uri.EscapeDataString(ech), Uri.EscapeDataString(FakeEch(60)))).Id, "Another ECH list is another link");
        Check(ProxyProfile.Explain("trojan://secret@h.example:443?ech=" + ech.Replace("+", "%2B")) == null && !ProxyProfile.Explain("trojan://secret@h.example:443?ech=%%%").ToString().Contains("%%%"), "The explanation of a broken ECH holds none of its text");

        // подпись: для показа, не влияет на подключение и идентификатор
        string basic = "trojan://secret@h.example:443";
        Check(ProxyProfile.Parse(basic + "#My%20server").Label == "My server" && ProxyProfile.Parse(basic + "#Hy2%3A-client01").Label == "Hy2:-client01", "The label is decoded");
        Check(ProxyProfile.Parse(basic).Label == null && ProxyProfile.Parse(basic + "#").Label == null && ProxyProfile.Parse(basic + "#%20%20").Label == null, "No label, no text");
        Check(ProxyProfile.Parse(basic + "#a%0Ab%09c%20%20d").Label == "abc d" && ProxyProfile.Parse(basic + "#x%00y%1Fz").Label == "xyz", "Control characters are dropped and spaces are collapsed");
        Check(ProxyProfile.Parse(basic + "#" + new string('w', 100)).Label == new string('w', 64), "A long label is cut");
        Check(ProxyProfile.TryParse(basic + "#bad%ZZ", out var oddLabel) && oddLabel.Label == "bad%ZZ", "A broken escape in the label does not spoil the link");
        Check(ProxyProfile.Parse(basic + "#one").Id == ProxyProfile.Parse(basic + "#two").Id, "The label is not part of the identity");
    }

    static string JsonText(Dictionary<string, object> value) => new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(value);

    /// <summary>Исходящее подключение sing-box в том виде, как оно попадёт в конфигурацию (массивы - object[]).</summary>
    static Dictionary<string, object> JObj(Dictionary<string, object> outbound) => JsonObject(JsonText(outbound));
}
