using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Zarp.Core;

// Подписка: https-адрес со списком ссылок на серверы (так их отдают панели вроде 3x-ui). Разбор ответа, загрузка, сохранённый список.
// Сети нет: ответы подставляются обработчиком HTTP.
static partial class Program
{
    const string SubUrl = "https://panel.example:2096/sub/s3cr3t-token";

    static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    static string SubLine(int n) => "vless://" + TestUuid + "@s" + n + ".example:443?security=tls&sni=s" + n + ".example#Server%20" + n;

    static void TestSubscriptionParsing()
    {
        // ссылки того же вида, что в подписках 3x-ui: VLESS XHTTP Reality со всеми добавками панели и Hysteria2 с ECH
        string ech = Uri.EscapeDataString(FakeEch());
        string xhttp = "vless://" + TestUuid + "@a.example:443?encryption=none&extra=" + Uri.EscapeDataString("{\"xPaddingBytes\":\"167-1300\"}") + "&fp=firefox&host=www.example.org&mode=auto&path=%2Fsample%2Fpath&pbk=" + TestRealityKey +
                       "&security=reality&sid=0a1b2c3d&sni=www.example.org&spx=%2Fa1b2&support-x25519mlkem768=true&type=xhttp&x_padding_bytes=167-1300#Main_one-client01";
        string hy2 = "hysteria2://auth-secret@b.example:5443?alpn=h3&ech=" + ech + "&fp=firefox&obfs=salamander&obfs-password=k&security=tls&sni=docs.example#Hy2%3A-client01";
        // комментарий в конце нужен, чтобы в base64 точно были оба знака, + и /, а значит, и - с _ в варианте для адресов
        string list = xhttp + "\n" + hy2 + "\n# " + new string('>', 40) + " " + new string('?', 40) + "\n";
        Check(B64(list).IndexOf('+') >= 0 && B64(list).IndexOf('/') >= 0, "The test list has both special characters of base64");

        // base64 в разных видах и обычный текст дают один и тот же список
        foreach (var body in new[]
        {
            B64(list), B64(list).TrimEnd('='), B64(list).Replace('+', '-').Replace('/', '_'), B64(list).Replace('+', '-').Replace('/', '_').TrimEnd('='),
            Regex_Wrap(B64(list), 40), "\uFEFF" + B64(list) + "\r\n", list, list.Replace("\n", "\r\n"), "  \n" + list + "\n  ",
        })
        {
            var result = Subscription.Parse(body);
            Check(result.Servers.Count == 2 && result.Unsupported == 0 && result.Refused == 0 && !result.Json && !result.Html, "Both servers are read from: " + (body.Length > 40 ? body.Substring(0, 40).Replace("\n", " ") : body) + " -> " + result.Servers.Count);
            Check(result.Servers[0].Link == xhttp && result.Servers[0].Profile.UsesXray && result.Servers[0].Profile.Label == "Main_one-client01" &&
                  result.Servers[1].Profile.Protocol == ProxyProtocol.Hysteria2 && result.Servers[1].Profile.Label == "Hy2:-client01", "The links and their labels are kept");
        }

        // что Zarp не поддерживает, не теряется молча: считается
        string mixed = string.Join("\n", new[]
        {
            "# comment", "", SubLine(1), "vmess://eyJhZGQiOiJ4In0=", "ss://YWVzOnBhc3M@h.example:1#x", "tuic://u:p@h.example:443", "not a link", SubLine(1),
            "vless://" + TestUuid + "@h.example:443?type=kcp", "trojan://secret@h.example:443?unknown=1", SubLine(2), "hy2://secret@h.example", "  " + SubLine(3) + "  ",
        });
        var parsed = Subscription.Parse(mixed);
        Check(parsed.Servers.Select(s => s.Profile.Label).SequenceEqual(new[] { "Server 1", "Server 2", null, "Server 3" }) && parsed.Unsupported == 4 && parsed.Refused == 2 && parsed.Truncated == 0,
            "Good links are kept (a repeated one once), other kinds and unreadable links are counted: servers " + parsed.Servers.Count + ", unsupported " + parsed.Unsupported + ", refused " + parsed.Refused);
        Check(Subscription.Parse(B64(mixed)).Servers.Count == 4, "The same list in base64");

        // JSON и веб-страница - не подписка со ссылками
        Check(Subscription.Parse("[{\"remarks\":\"x\"}]").Json && Subscription.Parse("{\"outbounds\":[]}").Json && Subscription.Parse(B64("[{\"a\":1}]")).Json && Subscription.Parse("[]").Servers.Count == 0, "JSON answers are named");
        Check(Subscription.Parse("<!DOCTYPE html><html><body>panel</body></html>").Html && Subscription.Parse("<html>x</html>").Html && !Subscription.Parse(SubLine(1)).Html, "A web page is named");
        foreach (var junk in new[] { "", "   ", "\n\n", "hello", "AAAA", "!!!!" })
            Check(Subscription.Parse(junk).Servers.Count == 0 && !Subscription.Parse(junk).Json, "Nothing is read from '" + junk + "'");
        // текст, который случайно читается как base64, остаётся текстом: считаются его строки, а не мусор после расшифровки
        var lookalike = Subscription.Parse("Forbidden\nForbidden\nForbidden");
        Check(lookalike.Servers.Count == 0 && lookalike.Unsupported == 3 && !lookalike.Json && !lookalike.Html, "A plain answer that looks like base64 stays text: " + lookalike.Unsupported);
        Check(Subscription.Parse(null).Servers.Count == 0, "No answer, no servers");

        // не больше MaxServers, лишние посчитаны
        var many = Subscription.Parse(string.Join("\n", Enumerable.Range(1, Subscription.MaxServers + 25).Select(SubLine)));
        Check(many.Servers.Count == Subscription.MaxServers && many.Truncated == 25, "Only " + Subscription.MaxServers + " servers are taken: " + many.Servers.Count + "/" + many.Truncated);

        // имена в списке: подпись, а без неё протокол и адрес; одинаковые различаются
        var strategies = Subscription.ToStrategies(new[]
        {
            ProxyProfile.Parse("trojan://s@one.example:443#Same"), ProxyProfile.Parse("trojan://s@two.example:443#same"), ProxyProfile.Parse("trojan://s@three.example:443"),
            ProxyProfile.Parse("vless://" + TestUuid + "@four.example:443#Unique"),
        });
        Check(strategies.Select(s => s.Name).SequenceEqual(new[] { "Same [one.example:443]", "same [two.example:443]", "Trojan: three.example:443", "Unique" }), "Names: " + string.Join(" | ", strategies.Select(s => s.Name)));
        var twins = Subscription.ToStrategies(new[] { ProxyProfile.Parse("trojan://a@x.example:443#T"), ProxyProfile.Parse("trojan://b@x.example:443#T") });
        Check(twins.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2 && twins.All(s => s.IsProxy && s.Id.StartsWith("proxy-") && !s.Name.Contains("secret")), "Identical names still get distinct names");
        Check(strategies[3].Profile.Title == "VLESS" && strategies[3].ProtocolTitle == "VLESS" && strategies.Select(s => s.Id).Distinct().Count() == 4, "Strategies keep the protocol and the identity");

        // адреса подписок: HTTPS, без имени и пароля, без #
        foreach (var good in new[] { SubUrl, "https://panel.example/sub", "https://panel.example:8443/a/b?token=1&x=2", "  " + SubUrl + "  " })
            Check(Subscription.IsUrl(good) && ProxySource.Kind(good) == ProxySourceKind.Subscription, "A subscription address: " + good.Trim());
        foreach (var bad in new[] { "http://panel.example/sub", "https://user:pass@panel.example/sub", "https://panel.example/sub#frag", "https://panel.example/a b", "ftp://panel.example/x", "https://", "panel.example/sub", "", "https://panel.example:99999/x" })
            Check(!Subscription.IsUrl(bad), "Not a subscription address: '" + bad + "'");
        Check(ProxySource.Kind("trojan://s@h.example:443") == ProxySourceKind.Link && ProxySource.Kind("hello") == ProxySourceKind.None && ProxySource.Kind("") == ProxySourceKind.None, "A link is a link, nonsense is nothing");
        Check(ProxySource.Explain(SubUrl) == null && ProxySource.Explain("trojan://s@h.example:443") == null, "Good sources need no explanation");
        Check(ProxySource.Explain("http://panel.example/sub").Key == "proxy.subscriptionHttps" && ProxySource.Explain("https://u:p@panel.example/sub").Key == "proxy.subscriptionUrl" &&
              ProxySource.Explain("HTTP://panel.example/sub").Key == "proxy.subscriptionHttps" && ProxySource.Explain("vmess://abc").Key == "proxy.scheme" && ProxySource.Explain("trojan://s@h:443?bogus=1").Key == "proxy.param",
            "Refused sources are explained: plain http, a bad https, other links");
        Check(!ProxySource.Explain("https://u:p@panel.example/sub").ToString().Contains("u:p") && Subscription.HostOf(SubUrl) == "panel.example" && Subscription.HostOf("junk") == "", "The explanation and the host name never show the token");
    }

    /// <summary>Строки по width знаков: так иногда отдают длинный base64.</summary>
    static string Regex_Wrap(string text, int width)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < text.Length; i += width) sb.Append(text, i, Math.Min(width, text.Length - i)).Append('\n');
        return sb.ToString();
    }

    static async Task TestSubscriptionDownloadAsync()
    {
        string good = B64(SubLine(1) + "\n" + SubLine(2));
        var http = new ScriptedHttp();
        Func<HttpMessageHandler> factory = () => new NonDisposing(http);

        // обычный ответ; запрос идёт как от Zarp, с именем клиента и без cookies
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(good) };
        var result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(result.Servers.Count == 2 && http.Requests.Count == 1 && http.Requests[0] == SubUrl, "A good answer is read with one request: " + http.Requests.Count);
        string agent = null;
        http.Respond = r => { agent = r.Headers.UserAgent.ToString(); return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(good) }; };
        await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(agent == "Zarp/1.0", "The first request names Zarp: " + agent);

        // панель отдала JSON: второй запрос под именем обычного клиента, и его ответ принимается
        var agents = new List<string>();
        http.Requests.Clear();
        http.Respond = r =>
        {
            agents.Add(r.Headers.UserAgent.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(agents.Count == 1 ? "[{\"remarks\":\"json\"}]" : good) };
        };
        result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(result.Servers.Count == 2 && agents.SequenceEqual(new[] { "Zarp/1.0", "v2rayN/7.0" }), "JSON gets a second try as another client: " + string.Join(",", agents));
        // оба раза не ссылки: итог первого ответа с пометкой
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[{\"remarks\":\"json\"}]") };
        result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(result.Servers.Count == 0 && result.Json, "Nothing usable in both answers: JSON is named");
        // вторая попытка не удалась по сети: остаётся ответ первой
        int calls = 0;
        http.Respond = r => { if (++calls == 2) throw new HttpRequestException("boom"); return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>page</html>") }; };
        result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(result.Html && result.Servers.Count == 0 && calls == 2, "A failed second try keeps the first answer");
        // оба ответа без ссылок, но разные: итог первого (ответ самому Zarp), а не второго
        calls = 0;
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(++calls == 1 ? "[{\"remarks\":\"json\"}]" : "<html>page</html>") };
        result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(calls == 2 && result.Json && !result.Html && result.Servers.Count == 0, "With two answers without links the first one is the result");

        // переходы: на другой HTTPS-адрес можно (до 5), на http, с именем и паролем, без адреса - нет
        http.Requests.Clear();
        http.Respond = r =>
        {
            string url = r.RequestUri.ToString();
            if (url == SubUrl) return Redirect("https://cdn.example/sub/1");
            if (url == "https://cdn.example/sub/1") return Redirect("/sub/2", HttpStatusCode.MovedPermanently);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(good) };
        };
        result = await Subscription.LoadAsync(SubUrl, factory, CancellationToken.None);
        Check(result.Servers.Count == 2 && http.Requests.SequenceEqual(new[] { SubUrl, "https://cdn.example/sub/1", "https://cdn.example/sub/2" }), "Redirects over https are followed: " + string.Join(" > ", http.Requests));
        foreach (var target in new[] { "http://cdn.example/x", "https://user:pw@cdn.example/x", "ftp://cdn.example/x", "https://cdn.example/x#f" })
        {
            http.Respond = r => r.RequestUri.ToString() == SubUrl ? Redirect(target) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(good) };
            var failure = await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
            Check(failure != null && failure.Reason == "redirect", "A redirect to '" + target + "' is refused: " + (failure?.Reason ?? "followed"));
        }
        http.Respond = r => Redirect("https://cdn.example/loop");
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "redirect", "Endless redirects stop");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.Found);
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "redirect", "A redirect without an address is refused");
        // ровно пять переходов допустимы, шестой уже нет
        foreach (var (hops, followed) in new[] { (5, true), (6, false) })
        {
            http.Respond = r =>
            {
                string path = r.RequestUri.AbsolutePath;
                int step = path.StartsWith("/hop/") ? int.Parse(path.Substring(5)) : 0;
                return step < hops ? Redirect("https://cdn.example/hop/" + (step + 1)) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(good) };
            };
            var outcome = await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None));
            Check(followed ? outcome == null : (outcome as SubscriptionException)?.Reason == "redirect", hops + " redirects in a row: " + (outcome == null ? "followed" : outcome.Message));
        }
        // обработчик по умолчанию: переходы вручную, без cookies, только gzip (deflate из .NET Framework читает лишь сырой поток, а серверы шлют его в обёртке zlib)
        using (var handler = (HttpClientHandler)Subscription.NewHandler())
            Check(!handler.AllowAutoRedirect && !handler.UseCookies && handler.AutomaticDecompression == DecompressionMethods.GZip, "The default handler follows redirects by hand, keeps no cookies and offers only gzip");

        // ошибки: причина без адреса и токена
        foreach (var code in new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.InternalServerError, HttpStatusCode.NoContent })
        {
            http.Respond = r => new HttpResponseMessage(code);
            var failure = await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
            Check(failure != null && failure.Reason == "http:" + (int)code && !failure.Message.Contains("s3cr3t") && failure.Describe().Key == "proxy.subHttp" && (string)failure.Describe().Args[0] == ((int)code).ToString(), "Status " + (int)code + " is named: " + failure?.Reason);
        }
        http.Respond = r => throw new HttpRequestException("The remote name could not be resolved: 'panel.example' " + SubUrl);
        var net = await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
        Check(net != null && net.Reason == "network" && !net.Message.Contains("panel") && !net.Message.Contains("s3cr3t") && net.Describe().Key == "proxy.subNetwork", "A network failure holds neither the address nor the token");
        http.Respond = r => throw new HttpRequestException("handshake", new WebException("trust", WebExceptionStatus.TrustFailure));
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "tls", "A certificate that cannot be trusted is named");
        http.Respond = r => throw new HttpRequestException("handshake", new WebException("channel", WebExceptionStatus.SecureChannelFailure));
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "tls", "A failed secure channel is named too");
        http.Respond = r => throw new HttpRequestException("handshake", new System.Security.Authentication.AuthenticationException("bad certificate"));
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "tls", "An authentication failure of TLS is named");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[0]) };
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "empty", "An empty answer is named");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[Subscription.MaxBytes + 1]) };
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "big", "A too large answer is refused");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new LimitlessStream()) };
        Check((await Catch(async () => await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException)?.Reason == "big", "An endless answer is cut at the limit");
        var exactly = new byte[Subscription.MaxBytes];
        for (int i = 0; i < exactly.Length; i++) exactly[i] = (byte)'a';
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(exactly) };
        Check((await Subscription.DownloadAsync(SubUrl, factory, "Zarp/1.0", CancellationToken.None)).Length == Subscription.MaxBytes, "An answer of exactly the limit is accepted");
        var notAddress = await Catch(async () => await Subscription.DownloadAsync("http://panel.example/sub", factory, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
        Check(notAddress != null && notAddress.Reason == "redirect", "A plain http address is never requested");

        // отмена пользователем - это отмена, а не сетевая ошибка; зависший ответ не держит загрузку вечно
        var stall = new CancellableHttp();
        using (var cancel = new CancellationTokenSource())
        {
            var pending = Subscription.DownloadAsync(SubUrl, () => new NonDisposing(stall), "Zarp/1.0", cancel.Token);
            await stall.Entered.Task;
            cancel.Cancel();
            var cancelled = await Catch(async () => await pending);
            Check(cancelled is OperationCanceledException, "Cancelling is a cancellation, not a failure: " + cancelled?.GetType().Name);
        }
    }

    sealed class LimitlessStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) { for (int i = 0; i < count; i++) buffer[offset + i] = (byte)'a'; return count; }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    static async Task<Exception> Catch(Func<Task> action)
    {
        try { await action(); return null; }
        catch (Exception e) { return e; }
    }

    static void TestSubscriptionCache()
    {
        string file = Path.Combine(_data, "cache-" + Guid.NewGuid().ToString("N"), "subscription.json");
        var cache = new SubscriptionCache(file);
        Check(cache.Load(SubUrl) == null, "Nothing is saved at first");
        var links = new[] { SubLine(1), SubLine(2) };
        var when = new DateTime(2026, 10, 11, 6, 30, 0, DateTimeKind.Utc);
        cache.Save(SubUrl, links, when);
        var snapshot = cache.Load(SubUrl);
        Check(snapshot != null && snapshot.Links.SequenceEqual(links) && snapshot.Updated == when, "A saved list comes back with its time");
        Check(cache.Load(SubUrl + "x") == null && cache.Load("https://other.example/sub") == null && cache.Load("  " + SubUrl + "  ") != null, "The list belongs to its address (spaces around do not matter)");
        string text = File.ReadAllText(file);
        Check(!text.Contains("s3cr3t") && !text.Contains("panel.example"), "The address and its token are not in the file, only a hash");
        Check(text.Contains(TestUuid), "The links are (they are needed to connect)");
        cache.Save(SubUrl, new[] { SubLine(3) }, when.AddHours(1));
        Check(cache.Load(SubUrl).Links.Single() == SubLine(3) && cache.Load(SubUrl).Updated == when.AddHours(1) && !File.Exists(file + ".tmp"), "Saving again replaces the list and leaves no temporary file");
        File.WriteAllText(file, "{broken");
        Check(cache.Load(SubUrl) == null, "A broken file is no list");
        File.WriteAllText(file, "{\"source\":\"x\",\"links\":[]}");
        Check(cache.Load(SubUrl) == null, "A file of another address is no list");
        File.WriteAllText(file, "[1,2,3]");
        Check(cache.Load(SubUrl) == null, "A file of the wrong shape is no list");
        cache.Save(SubUrl, links, when);
        cache.Delete();
        Check(cache.Load(SubUrl) == null && !File.Exists(file), "Deleting removes the list");
        cache.Delete();
        // из файла берутся только строки
        cache.Save(SubUrl, links, when);
        File.WriteAllText(file, File.ReadAllText(file).Replace("\"links\":[", "\"links\":[5,null,{\"a\":1},"));
        Check(cache.Load(SubUrl).Links.SequenceEqual(links), "Items that are not strings are ignored");
    }

    // ------------------------------------------------------------------ настоящий HTTPS на localhost

    /// <summary>Мини-сервер HTTPS на localhost с самоподписанным сертификатом: настоящие TLS, заголовки, сжатие, переходы и обрывы.</summary>
    sealed class LocalHttpsServer : IDisposable
    {
        readonly System.Net.Sockets.TcpListener _listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        readonly System.Security.Cryptography.X509Certificates.X509Certificate2 _certificate;
        volatile bool _stopped;
        public readonly List<string> Agents = new List<string>();
        public readonly List<string> Paths = new List<string>();
        public readonly string Body;
        public string Thumbprint => _certificate.Thumbprint;
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public string Url(string path) => "https://127.0.0.1:" + Port + path;

        public LocalHttpsServer(string body)
        {
            Body = body;
            using (var rsa = System.Security.Cryptography.RSA.Create(2048))
            {
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost", rsa,
                    System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var names = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
                names.AddDnsName("localhost");
                names.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(names.Build());
                using (var self = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2)))
                    _certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(self.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "test"), "test",
                        System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            }
            _listener.Start();
            new Thread(Accept) { IsBackground = true }.Start();
        }

        void Accept()
        {
            while (!_stopped)
            {
                System.Net.Sockets.TcpClient client;
                try { client = _listener.AcceptTcpClient(); }
                catch (Exception) { return; }
                new Thread(() => Serve(client)) { IsBackground = true }.Start();
            }
        }

        void Serve(System.Net.Sockets.TcpClient client)
        {
            try
            {
                using (client)
                using (var tls = new System.Net.Security.SslStream(client.GetStream(), false))
                {
                    tls.AuthenticateAsServer(_certificate, false, System.Security.Authentication.SslProtocols.Tls12, false);
                    var head = new StringBuilder();
                    int b;
                    while (!head.ToString().EndsWith("\r\n\r\n") && (b = tls.ReadByte()) >= 0) head.Append((char)b);
                    var lines = head.ToString().Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                    string path = lines[0].Split(' ')[1];
                    string agent = lines.Skip(1).Select(l => l.Split(new[] { ": " }, 2, StringSplitOptions.None)).Where(p => p.Length == 2 && p[0].Equals("User-Agent", StringComparison.OrdinalIgnoreCase)).Select(p => p[1]).FirstOrDefault() ?? "";
                    lock (Agents) { Agents.Add(agent); Paths.Add(path); }

                    void Send(string status, byte[] body, string extra = "", long? length = null)
                    {
                        var header = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\n" + (length == null && body == null ? "" : "Content-Length: " + (length ?? body.Length) + "\r\n") + extra + "Connection: close\r\n\r\n");
                        tls.Write(header, 0, header.Length);
                        if (body != null) tls.Write(body, 0, body.Length);
                        tls.Flush();
                    }

                    switch (path)
                    {
                        case "/list": Send("200 OK", Encoding.UTF8.GetBytes(Body)); break;
                        case "/agent-json": Send("200 OK", Encoding.UTF8.GetBytes(agent.StartsWith("Zarp") ? "[{\"remarks\":\"json\"}]" : Body)); break;
                        case "/gzip":
                            {
                                var packed = new MemoryStream();
                                using (var zip = new System.IO.Compression.GZipStream(packed, System.IO.Compression.CompressionMode.Compress, true)) { var raw = Encoding.UTF8.GetBytes(Body); zip.Write(raw, 0, raw.Length); }
                                Send("200 OK", packed.ToArray(), "Content-Encoding: gzip\r\n");
                                break;
                            }
                        case "/redirect": Send("302 Found", null, "Location: /list\r\n", 0); break;
                        case "/redirect-absolute": Send("302 Found", null, "Location: " + Url("/redirect") + "\r\n", 0); break;
                        case "/redirect-plain": Send("302 Found", null, "Location: http://127.0.0.1:" + Port + "/list\r\n", 0); break;
                        case "/forbidden": Send("403 Forbidden", Encoding.ASCII.GetBytes("no")); break;
                        case "/empty": Send("200 OK", new byte[0]); break;
                        case "/big": Send("200 OK", null, "", 3L << 20); break;
                        case "/endless":
                            {
                                var header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                                tls.Write(header, 0, header.Length);
                                var chunk = new byte[16 * 1024];
                                for (int i = 0; i < chunk.Length; i++) chunk[i] = (byte)'a';
                                for (int i = 0; i < 400; i++) tls.Write(chunk, 0, chunk.Length); // 6,4 МБ: больше предела
                                break;
                            }
                        case "/stall": Send("200 OK", null, "", 100); Thread.Sleep(20000); break;
                        case "/silent": Thread.Sleep(20000); break;
                        default: Send("404 Not Found", new byte[0]); break;
                    }
                }
            }
            catch (Exception) { } // клиент оборвал соединение: так и задумано
        }

        public void Dispose()
        {
            _stopped = true;
            try { _listener.Stop(); } catch { }
            _certificate.Dispose();
        }
    }

    /// <summary>Обработчик HTTP по умолчанию, который доверяет одному сертификату (тестовому серверу): всё остальное - настройки программы.</summary>
    static Func<HttpMessageHandler> TrustOnly(string thumbprint) => () =>
    {
        var handler = (HttpClientHandler)Subscription.NewHandler();
        handler.ServerCertificateCustomValidationCallback = (message, certificate, chain, errors) => string.Equals(certificate.GetCertHashString(), thumbprint, StringComparison.OrdinalIgnoreCase);
        return handler;
    };

    /// <summary>
    /// То же, что TestSubscriptionDownloadAsync, но на настоящем сетевом стеке: TLS с проверкой сертификата, заголовки, сжатие, переходы,
    /// обрывы и пределы. Ответы подставлять нельзя, поэтому сервер свой, на localhost.
    /// </summary>
    static async Task TestSubscriptionRealHttpsAsync()
    {
        string list = B64(SubLine(1) + "\n" + SubLine(2));
        using (var server = new LocalHttpsServer(list))
        {
            var trust = TrustOnly(server.Thumbprint);
            Func<string, Task<string>> get = async path => await Subscription.DownloadAsync(server.Url(path), trust, "Zarp/1.0", CancellationToken.None);
            Func<string, Task<string>> reason = async path => ((await Catch(async () => await get(path))) as SubscriptionException)?.Reason;

            Check(await get("/list") == list && server.Agents.Last() == "Zarp/1.0" && server.Paths.Last() == "/list", "A real request over TLS: the answer comes whole and the client is named");
            Check(await get("/gzip") == list, "A compressed answer is unpacked");
            Check(await get("/redirect") == list && await get("/redirect-absolute") == list, "Redirects, relative and absolute, are followed");
            Check(await reason("/redirect-plain") == "redirect", "A redirect to plain http is refused");
            Check(await reason("/forbidden") == "http:403" && await reason("/missing") == "http:404", "Statuses of the panel are named");
            Check(await reason("/empty") == "empty", "An empty answer is named");
            Check(await reason("/big") == "big" && await reason("/endless") == "big", "Too large answers are refused, with and without a length");
            var loaded = await Subscription.LoadAsync(server.Url("/agent-json"), trust, CancellationToken.None);
            Check(loaded.Servers.Count == 2 && server.Agents.Skip(server.Agents.Count - 2).SequenceEqual(new[] { "Zarp/1.0", "v2rayN/7.0" }), "A JSON answer to Zarp gets a second try as another client: " + string.Join(",", server.Agents));

            // отмена обрывает зависший ответ быстро
            using (var cancel = new CancellationTokenSource())
            {
                var clock = System.Diagnostics.Stopwatch.StartNew();
                var pending = Subscription.DownloadAsync(server.Url("/stall"), trust, "Zarp/1.0", cancel.Token);
                await Task.Delay(500);
                cancel.Cancel();
                var stopped = await Catch(async () => await pending);
                Check(stopped is OperationCanceledException && clock.Elapsed.TotalSeconds < 8, "A stalled answer is cut at once when cancelled: " + stopped?.GetType().Name + " after " + clock.Elapsed.TotalSeconds + " s");
            }

            // срок всего запроса: ответ, который не начался, и ответ, который остановился на середине, обрываются, когда срок вышел
            var deadline = typeof(Subscription).GetField("Deadline", PrivateStatic);
            var normalDeadline = (TimeSpan)deadline.GetValue(null);
            deadline.SetValue(null, TimeSpan.FromSeconds(2));
            try
            {
                foreach (var path in new[] { "/silent", "/stall" })
                {
                    var clock = System.Diagnostics.Stopwatch.StartNew();
                    var timedOut = await Catch(async () => await get(path)) as SubscriptionException;
                    Check(timedOut != null && timedOut.Reason == "timeout" && timedOut.Describe().Key == "proxy.subTimeout" && clock.Elapsed.TotalSeconds < 10,
                        "An answer that does not come ends at the deadline (" + path + "): " + (timedOut?.Reason ?? "no failure") + " after " + clock.Elapsed.TotalSeconds + " s");
                }
            }
            finally { deadline.SetValue(null, normalDeadline); }

            // сертификат, которому система не доверяет, называется своим именем, а токена в тексте нет
            var untrusted = await Catch(async () => await Subscription.DownloadAsync(server.Url("/list?token=s3cr3t"), null, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
            Check(untrusted != null && untrusted.Reason == "tls" && !untrusted.Message.Contains("s3cr3t") && untrusted.Describe().Key == "proxy.subTls", "A certificate that is not trusted is named: " + untrusted?.Reason);
        }
        // порт, где никто не слушает
        int closed = FreeTcpPort();
        var refused = await Catch(async () => await Subscription.DownloadAsync("https://127.0.0.1:" + closed + "/x?token=s3cr3t", null, "Zarp/1.0", CancellationToken.None)) as SubscriptionException;
        Check(refused != null && refused.Reason == "network" && !refused.Message.Contains("s3cr3t"), "A closed port is a network failure: " + refused?.Reason);
    }

    // ------------------------------------------------------------------ движок с несколькими серверами

    static Engine SubscriptionEngine(out FakeProxy fake, IEnumerable<string> links, DateTime? updated = null, ScriptedHttp http = null)
    {
        var engine = ProxyEngine(out fake);
        SetPrivate(engine, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(http ?? new ScriptedHttp { Respond = r => throw new HttpRequestException("no network in this test") })));
        engine.Config.ProxyUri = SubUrl;
        if (links != null) engine.Subscriptions.Save(SubUrl, links, updated ?? DateTime.UtcNow);
        engine.ReloadStrategies();
        return engine;
    }

    static string ServerLink(string host, string label, string extra = "") =>
        "trojan://secret-" + host + "@" + host + ":443?sni=" + host + extra + "#" + Uri.EscapeDataString(label);

    /// <summary>Имя сервера из имени пары «стратегия + сервер».</summary>
    static string ServerName(Strategy pair) => pair.Name.Substring(pair.Name.IndexOf(" + ", StringComparison.Ordinal) + 3);

    /// <summary>Серверы движка в порядке их появления в списке пар.</summary>
    static List<string> ServerNames(Engine engine) => engine.Strategies.Select(ServerName).Distinct().ToList();

    /// <summary>Пара стратегии zapret2 (по id из TestZapretStrategies) и сервера (по имени).</summary>
    static Strategy PairOf(Engine engine, string strategyId, string server) =>
        engine.Strategies.Single(s => s.Id.StartsWith(strategyId + "@", StringComparison.Ordinal) && ServerName(s) == server);

    static async Task TestSubscriptionEngineAsync()
    {
        string[] links = { ServerLink("a.example", "Alpha"), ServerLink("b.example", "Beta"), ServerLink("c.example", "Gamma") };
        var engine = SubscriptionEngine(out var fake, links);
        // серверу с TLS по TCP подходят две стратегии под TLS: пар вдвое больше, чем серверов; сначала по стратегиям, для каждой все серверы
        var ids = links.Select(l => ProxyProfile.Parse(l).Id).ToArray();
        Check(engine.ProxyMode && ServerNames(engine).SequenceEqual(new[] { "Alpha", "Beta", "Gamma" }) && engine.Candidates.Count == 6 && engine.Strategies.All(s => s.IsProxy && s.UsesZapret),
            "A subscription gives a pair of every strategy and every server: " + string.Join(",", engine.Strategies.Select(s => s.Name)));
        Check(engine.Strategies.Select(s => s.Id).SequenceEqual(new[] { "t-split@" + ids[0], "t-split@" + ids[1], "t-split@" + ids[2], "t-disorder@" + ids[0], "t-disorder@" + ids[1], "t-disorder@" + ids[2] }),
            "The order of the search: a strategy against all servers, then the next strategy: " + string.Join(",", engine.Strategies.Select(s => s.Name)));
        Check(engine.Selected == null, "Nothing is chosen yet");
        // в сохранённом списке (его могли править руками или записать другой версией) одна и та же ссылка не даёт двух серверов, а подпись в идентификатор не входит
        var twice = SubscriptionEngine(out var twin, new[] { ServerLink("a.example", "Alpha"), ServerLink("a.example", "Alpha again"), ServerLink("b.example", "Beta") });
        Check(twice.Strategies.Count == 4 && twice.Strategies.Select(s => s.Id).Distinct().Count() == 4 && ServerNames(twice).SequenceEqual(new[] { "Alpha", "Beta" }),
            "A link repeated in the saved list is one server: " + string.Join(",", twice.Strategies.Select(s => s.Name)));

        // подключение без выбранной пары: проверяются пары по порядку до нужного числа рабочих, лучшая по времени и пингу берётся
        var timing = new Dictionary<string, int[]> { ["a.example"] = new[] { 300, 90 }, ["b.example"] = new[] { 100, 30 }, ["c.example"] = new[] { 200, 10 } };
        fake.Measure = s => s.Tun ? new ProxyMeasure { Ok = true, FirstMs = 1, PingMs = 1 } : new ProxyMeasure { Ok = true, FirstMs = timing[s.Profile.Host][0], PingMs = timing[s.Profile.Host][1] };
        await engine.ConnectAsync();
        var beta = PairOf(engine, "t-split", "Beta");
        Check(engine.State == EngineState.Connected && engine.Selected == beta && engine.Config.SelectedStrategyId == beta.Id, "The best of the verified pairs is connected and remembered: " + engine.State + " / " + engine.Selected?.Name);
        Check(engine.Config.Results.Keys.OrderBy(k => k).SequenceEqual(new[] { "t-split@" + ids[0], "t-split@" + ids[1], "t-split@" + ids[2] }.OrderBy(k => k)) && engine.Config.Results.Values.All(r => r.Ok && r.Confirmed),
            "A quick scan stops after three working pairs: " + string.Join(",", engine.Config.Results.Keys));
        Check(fake.Started.Last().Tun && fake.Started.Last().Profile.Id == beta.Profile.Id && fake.Started.Count(s => !s.Tun) >= 6, "Each pair is tried twice without the adapter, the winner then gets the adapter: " + fake.Started.Count);
        foreach (var host in new[] { "a.example", "b.example", "c.example" })
            Check(fake.Resolved.Count(h => h == host) == 1, host + " is resolved once per operation, not once per try or per pair: " + string.Join(",", fake.Resolved));
        Check(engine.Zapret.Running && engine.Zapret.RunningStrategyArgs() == ArgsOf("t-split") && ZapretConfig(engine).Contains("ip.DstAddr==203.0.113.9"),
            "winws2 runs with the strategy of the chosen pair");

        // выбранная пара перестала работать: остальные проверенные пробуются по очереди
        await engine.DisconnectAsync();
        fake.Resolved.Clear();
        fake.Measure = s => s.Profile.Host == "b.example" && engine.Zapret.RunningStrategyArgs() == ArgsOf("t-split") ? new ProxyMeasure { Error = "timeout" }
            : new ProxyMeasure { Ok = true, FirstMs = timing[s.Profile.Host][0], PingMs = timing[s.Profile.Host][1] };
        await engine.ConnectAsync();
        var gamma = PairOf(engine, "t-split", "Gamma");
        Check(engine.State == EngineState.Connected && engine.Selected == gamma, "When the chosen pair fails the next best one is connected: " + engine.State + " / " + engine.Selected?.Name + " / " + engine.Detail);
        Check(!engine.Config.Results[beta.Id].Ok, "The failure of the old choice is remembered");
        Check(fake.Resolved.Count(h => h == "b.example") == 1 && fake.Resolved.Count(h => h == "c.example") == 1, "The next operation resolves the names again, once each: " + string.Join(",", fake.Resolved));

        // все не отвечают: ничего не подключено, адаптер не запускался, winws2 выключен
        await engine.DisconnectAsync();
        fake.Measure = s => new ProxyMeasure { Error = "timeout" };
        fake.Started.Clear();
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && !engine.Zapret.Running && fake.Started.All(s => !s.Tun), "Nothing connects when no pair passes: " + engine.State + " " + engine.Detail);

        // одна ссылка: каждая её пара проверяется по разу
        var single = ProxyEngine(out var one);
        one.Measure = s => new ProxyMeasure { Error = "timeout" };
        await single.ConnectAsync();
        Check(single.State == EngineState.Idle && one.Started.Count == 2, "A single link is tried once with each of its strategies: " + one.Started.Count);

        // два сервера на одном имени (порты разные): имя разрешается один раз на оба
        var shared = SubscriptionEngine(out var sharedFake, new[] { ServerLink("a.example", "First"), "trojan://secret-a2@a.example:8443?sni=a.example#Second" });
        sharedFake.Measure = s => new ProxyMeasure { Ok = true, FirstMs = 100, PingMs = 30 };
        await shared.ConnectAsync();
        Check(shared.State == EngineState.Connected && shared.Strategies.Count == 4 && sharedFake.Resolved.Count(h => h == "a.example") == 1, "Servers on one name share one lookup: " + string.Join(",", sharedFake.Resolved));
        Check(ZapretConfig(shared).Contains("'--wf-tcp-out=443'") || ZapretConfig(shared).Contains("'--wf-tcp-out=8443'"), "winws2 follows the port of the pair that connected");

        // DPI пропускает только одно сочетание: поиск находит его среди всех пар
        var dpi = SubscriptionEngine(out var dpiFake, links);
        dpiFake.Measure = s => s.Profile.Host == "c.example" && dpi.Zapret.RunningStrategyArgs() == ArgsOf("t-disorder")
            ? new ProxyMeasure { Ok = true, FirstMs = 150, PingMs = 20 } : new ProxyMeasure { Error = "timeout" };
        await dpi.ConnectAsync();
        Check(dpi.State == EngineState.Connected && dpi.Selected == PairOf(dpi, "t-disorder", "Gamma") && dpiFake.Started.Count(s => !s.Tun) == 8,
            "The only passing combination is found among all pairs: " + dpi.State + " / " + dpi.Selected?.Name + " / " + dpiFake.Started.Count);
        Check(dpi.Config.Results.Values.Count(r => r.Ok) == 1 && dpi.Config.Results.Count == 6 && dpi.Zapret.RunningStrategyArgs() == ArgsOf("t-disorder"),
            "Five pairs failed, one passed, and winws2 runs with its strategy: " + dpi.Config.Results.Count);

        // полный поиск проверяет все пары, у разных протоколов свои стратегии: TLS по TCP и QUIC
        string hysteria = "hysteria2://auth@h.example:5443?sni=h.example#Quic";
        var mixed = SubscriptionEngine(out var mixedFake, new[] { ServerLink("a.example", "Alpha"), hysteria });
        Check(mixed.Strategies.Select(s => s.Id.Split('@')[0]).SequenceEqual(new[] { "t-split", "q-fake", "t-disorder", "q-fake3" }) &&
              mixed.Strategies.Where(s => s.Id.StartsWith("t-")).All(s => ServerName(s) == "Alpha") && mixed.Strategies.Where(s => s.Id.StartsWith("q-")).All(s => ServerName(s) == "Quic"),
            "TLS strategies go with the TLS server, QUIC strategies with the QUIC one: " + string.Join(",", mixed.Strategies.Select(s => s.Name)));
        await mixed.SearchAsync(full: true);
        Check(mixed.Config.Results.Count == 4 && mixed.Config.Results.Values.All(r => r.Ok), "A full scan tests every pair: " + mixed.Config.Results.Count);
        Check(mixed.State == EngineState.Connected && mixed.Selected != null, "and connects with the best: " + mixed.State);
        var quic = PairOf(mixed, "q-fake", "Quic");
        await mixed.UseStrategyAsync(quic);
        string quicConfig = ZapretConfig(mixed);
        Check(mixed.State == EngineState.Connected && mixed.Selected == quic && quicConfig.Contains("udp.DstPort==5443") && quicConfig.Contains("'--wf-raw-part=") && !quicConfig.Contains("--wf-tcp-out") && quicConfig.TrimEnd().EndsWith(ArgsOf("q-fake")),
            "A QUIC server is intercepted over UDP at its own port: " + quicConfig);
    }

    static async Task TestSubscriptionRefreshAsync()
    {
        string[] first = { ServerLink("a.example", "Alpha"), ServerLink("b.example", "Beta") };
        string[] second = { ServerLink("b.example", "Beta"), ServerLink("d.example", "Delta"), ServerLink("e.example", "Echo") };
        string answer = B64(string.Join("\n", second));
        var http = new ScriptedHttp { Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(answer) } };
        var logged = new List<string>();
        Action<string> sink = line => { lock (logged) logged.Add(line); };
        bool Logged(string text) { lock (logged) return logged.Any(l => l.Contains(text)); }
        Log.Line += sink;
        string refreshFailed = L.T("log.subscriptionFailedOld", new SubscriptionException("network").Describe());
        string loadFailed = L.T("log.subscriptionFailed", new SubscriptionException("network").Describe());

        // свежий список не обновляется при подключении: сети не нужно
        var engine = SubscriptionEngine(out var fake, first, DateTime.UtcNow.AddHours(-1), http);
        await engine.ConnectAsync();
        Check(http.Requests.Count == 0 && ServerNames(engine).Count == 2 && engine.State == EngineState.Connected, "A fresh list is used as it is: requests " + http.Requests.Count);

        // старше срока: обновляется при подключении, пропавший сервер и его результаты исчезают, новые появляются
        var beta = PairOf(engine, "t-split", "Beta");
        Check(engine.Config.Results.ContainsKey(beta.Id), "Setup: the pair with Beta has a result");
        await engine.DisconnectAsync();
        engine.Subscriptions.Save(SubUrl, first, DateTime.UtcNow.AddHours(-13));
        engine.Config.SelectedStrategyId = PairOf(engine, "t-split", "Alpha").Id;
        await engine.ConnectAsync();
        Check(http.Requests.Count == 1 && ServerNames(engine).SequenceEqual(new[] { "Beta", "Delta", "Echo" }), "An old list is refreshed on connect: " + string.Join(",", ServerNames(engine)));
        Check(engine.Strategies.Any(s => s.Id == beta.Id) && engine.Config.Results.ContainsKey(beta.Id) && engine.Config.Results.Keys.All(id => engine.Strategies.Any(s => s.Id == id)),
            "Results of vanished servers are dropped, those that stay are kept");
        Check(engine.State == EngineState.Connected && engine.Selected != null && ServerName(engine.Selected) != "Alpha" && DateTime.UtcNow - engine.Subscriptions.Load(SubUrl).Updated < TimeSpan.FromMinutes(5), "The new list is saved and used");

        // обновить не удалось, а список есть: работаем со старым
        await engine.DisconnectAsync();
        engine.Subscriptions.Save(SubUrl, first, DateTime.UtcNow.AddDays(-3));
        engine.ReloadStrategies();
        engine.Config.SelectedStrategyId = null;
        http.Respond = r => throw new HttpRequestException("down");
        http.Requests.Clear();
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && ServerNames(engine).SequenceEqual(new[] { "Alpha", "Beta" }) && http.Requests.Count >= 1, "A failed refresh keeps the old list working: " + engine.State + " / " + engine.Detail);
        Check(engine.Subscriptions.Load(SubUrl).Updated < DateTime.UtcNow.AddDays(-2), "The old list keeps its old date");
        Check(Logged(refreshFailed) && !Logged(loadFailed), "The log says that the saved list is used: " + refreshFailed);

        // старый список, а панель ответила без подходящих серверов: работаем со старым, как при недоступной панели
        var withoutServers = new ScriptedHttp { Respond = r => Text("[]") };
        engine = SubscriptionEngine(out fake, first, DateTime.UtcNow.AddDays(-2), withoutServers);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && withoutServers.Requests.Count >= 1 && ServerNames(engine).SequenceEqual(new[] { "Alpha", "Beta" }),
            "An answer without servers does not replace an old list: " + engine.State + " / " + engine.Detail);
        // списка нет совсем, а панель ответила: список загружается и сразу используется
        var firstTime = new ScriptedHttp { Respond = r => Text(answer) };
        engine = SubscriptionEngine(out fake, null, null, firstTime);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && ServerNames(engine).Count == 3 && engine.Subscriptions.Load(SubUrl) != null, "With no list at all the first connection loads it: " + engine.State + " / " + engine.Detail);

        // списка нет и загрузить нельзя: причина названа, ничего не запускается
        engine = SubscriptionEngine(out fake, null);
        Check(engine.Strategies.Count == 0, "No list yet");
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.subscriptionFailed") && fake.Started.Count == 0 && !engine.Zapret.Running, "Without a list and without the network the connection says why: " + engine.Detail);
        Check(Logged(loadFailed), "The log says that the list could not be loaded: " + loadFailed);
        // ответ без подходящих серверов
        http = new ScriptedHttp { Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(B64("vmess://abc\nss://def")) } };
        engine = SubscriptionEngine(out fake, null, null, http);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.subscriptionEmpty") && fake.Started.Count == 0 && engine.Subscriptions.Load(SubUrl) == null, "An answer with no usable servers is reported and saves nothing: " + engine.Detail);
        // список есть, но пуст: сообщение о пустой подписке
        engine = SubscriptionEngine(out fake, new string[0]);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.subscriptionEmpty") && fake.Started.Count == 0, "An empty saved list is reported: " + engine.Detail);

        // загрузка для окна: список сохраняется, настройки не меняются, ошибки - SubscriptionException, старый список переживает пустой ответ
        engine = SubscriptionEngine(out fake, first);
        http = new ScriptedHttp { Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(answer) } };
        SetPrivate(engine, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(http)));
        var loaded = await engine.LoadSubscriptionAsync(SubUrl);
        Check(loaded.Servers.Count == 3 && engine.Subscriptions.Load(SubUrl).Links.Count == 3 && ServerNames(engine).Count == 2 && engine.Config.ProxyUri == SubUrl, "Loading saves the list but does not change the strategies by itself");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") };
        loaded = await engine.LoadSubscriptionAsync(SubUrl);
        Check(loaded.Servers.Count == 0 && engine.Subscriptions.Load(SubUrl).Links.Count == 3, "An answer without servers leaves the saved list alone");
        http.Respond = r => new HttpResponseMessage(HttpStatusCode.Forbidden);
        var failure = await Catch(async () => await engine.LoadSubscriptionAsync(SubUrl)) as SubscriptionException;
        Check(failure != null && failure.Reason == "http:403", "A refusal of the panel is reported");
        Check(await Catch(async () => await engine.LoadSubscriptionAsync("http://panel.example/sub")) is SubscriptionException, "A plain http address is refused before any request");

        // применение настроек: адрес подписки подхватывает сохранённый список; смена адреса сбрасывает результаты и выбор
        engine.Config.SelectedStrategyId = engine.Strategies[0].Id;
        engine.Config.Results[engine.Strategies[0].Id] = new TestResult { StrategyId = engine.Strategies[0].Id, Ok = true, Confirmed = true };
        Check(engine.ApplyConnection("", true, SubUrl) && ServerNames(engine).Count == 3 && engine.Config.SelectedStrategyId != null, "Applying the same address keeps results and the choice, and takes the saved list");
        Check(engine.ApplyConnection("", true, "https://other.example/sub") && engine.Strategies.Count == 0 && engine.Config.SelectedStrategyId == null && engine.Config.Results.Count == 0, "Another address starts from nothing until it is loaded");
        Check(engine.ApplyConnection("", true, "trojan://s@single.example:443#One") && engine.Strategies.Count == 2 && ServerNames(engine).SequenceEqual(new[] { "One" }), "Back to a single link, named by its label");
        Log.Line -= sink;
    }

    static async Task TestSubscriptionAdoptionAsync()
    {
        string[] links = { ServerLink("a.example", "Alpha"), ServerLink("b.example", "Beta"), ServerLink("c.example", "Gamma") };

        // после перезапуска Zarp работает тот сервер подписки, на который указывает сохранённое состояние, а не выбранный;
        // из его пар берётся та, чья стратегия включена в winws2
        var engine = SubscriptionEngine(out var fake, links);
        var gamma = PairOf(engine, "t-disorder", "Gamma");
        engine.Config.SelectedStrategyId = PairOf(engine, "t-split", "Alpha").Id;
        Check(await engine.Zapret.StartAsync(gamma, ZapretTarget.For("203.0.113.9", gamma.Profile)) == null, "Setup: winws2 runs with the strategy of Gamma's second pair");
        fake.IsRunning = true;
        var asked = new List<string>();
        fake.AdoptFor = p => { asked.Add(p.Host); return p.Host == "c.example" ? new ProxySession { Profile = p, Port = 18080, User = "zarp", Password = "pw", Tun = true } : null; };
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Connected && engine.Config.SelectedStrategyId == gamma.Id && engine.Selected == gamma, "The pair that is really running is taken over and shown as chosen: " + engine.State + " / " + engine.Selected?.Name);
        Check(asked.First() == "a.example" && asked.Contains("c.example") && asked.Distinct().Count() == asked.Count, "The chosen server is asked first, the rest after it, each server once: " + string.Join(",", asked));

        // выбранный сервер совпал: он спрашивается первым (хотя стоит в списке последним), остальные уже не нужны
        engine = SubscriptionEngine(out fake, links);
        var gammaSplit = PairOf(engine, "t-split", "Gamma");
        engine.Config.SelectedStrategyId = gammaSplit.Id;
        fake.IsRunning = true;
        asked = new List<string>();
        fake.AdoptFor = p => { asked.Add(p.Host); return new ProxySession { Profile = p, Port = 18080, User = "zarp", Password = "pw", Tun = true }; };
        await engine.RefreshStateAsync();
        Check(asked.SequenceEqual(new[] { "c.example" }) && engine.Selected == gammaSplit, "When the chosen server matches, nobody else is asked and its chosen pair stays: " + string.Join(",", asked));

        // ни один не подхвачен, а что-то работает: остатки останавливаются; каждый сервер спрошен один раз, а не по разу на каждую его пару
        engine = SubscriptionEngine(out fake, links);
        fake.IsRunning = true;
        asked = new List<string>();
        fake.AdoptFor = p => { asked.Add(p.Host); return null; };
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && fake.Stops > 0, "Leftovers that match no server are stopped");
        Check(asked.OrderBy(h => h).SequenceEqual(new[] { "a.example", "b.example", "c.example" }), "Every server is asked once, not once per pair: " + string.Join(",", asked));

        // Xray нужен, если он нужен хоть одному серверу списка; обычным серверам его не готовят
        string xhttp = "vless://" + TestUuid + "@x.example:443?type=xhttp&security=tls#Xhttp";
        engine = SubscriptionEngine(out fake, new[] { ServerLink("a.example", "Alpha"), xhttp });
        await engine.ConnectAsync();
        Check(fake.BridgePrepared >= 1 && engine.State == EngineState.Connected, "A list with an XHTTP server prepares the bridge: " + fake.BridgePrepared);
        engine = SubscriptionEngine(out fake, links);
        await engine.ConnectAsync();
        Check(fake.BridgePrepared == 0 && engine.State == EngineState.Connected, "A list without XHTTP does not touch the bridge: " + fake.BridgePrepared);
    }

    // ------------------------------------------------------------------ окно

    /// <summary>Ответ, который тест отдаёт, когда решит; честно реагирует на отмену.</summary>
    sealed class GatedHttp : HttpMessageHandler
    {
        public readonly TaskCompletionSource<HttpResponseMessage> Gate = new TaskCompletionSource<HttpResponseMessage>();
        public int Requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Requests);
            ct.Register(() => Gate.TrySetCanceled());
            return Gate.Task;
        }
    }

    /// <summary>Крутит сообщения окон, пока условие не выполнится (загрузка в окне идёт асинхронно и возвращается в поток окна).</summary>
    static void PumpUntil(Func<bool> condition, int seconds = 10)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (clock.Elapsed.TotalSeconds < seconds && !condition())
        {
            Application.DoEvents();
            Thread.Sleep(15);
        }
        Application.DoEvents();
    }

    static HttpResponseMessage Text(string text) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(text) };

    static void TestConnectionFormSubscription()
    {
        var engine = NewEngine();
        var gate = new GatedHttp();
        SetPrivate(engine, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(gate)));
        using (var form = NewForm("ConnectionForm", engine))
        {
            PositionOffscreen(form);
            form.Show();
            Application.DoEvents();
            var link = GetPrivate<Control>(form, "_link");
            var save = GetPrivate<Button>(form, "_save");
            var status = GetPrivate<Label>(form, "_linkStatus");
            SetChecked(GetPrivate<Control>(form, "_useProxy"), true);

            // адрес подписки принимается; что с ним будет, сказано сразу, сервера пока неизвестны
            link.Text = SubUrl;
            Check(save.Enabled && status.Text == L.T("proxy.subscription", "panel.example") && !status.Text.Contains("s3cr3t"), "A subscription address is accepted and the token stays hidden: " + status.Text);

            // сохранение загружает список; пока ответа нет, окно ждёт
            save.PerformClick();
            Application.DoEvents();
            Check(status.Text == L.T("proxy.subscriptionLoading") && !save.Enabled && gate.Requests == 1 && engine.Config.ProxyUri == "", "While the list loads the window says so and waits, nothing is saved: " + status.Text);
            gate.Gate.SetResult(Text(B64(string.Join("\n", new[] { ServerLink("a.example", "Alpha"), ServerLink("b.example", "Beta"), "vmess://abc", "vless://" + TestUuid + "@x.example:443?type=xhttp&security=tls#Xhttp" }))));
            PumpUntil(() => engine.Config.ProxyUri == SubUrl);
            var snapshot = engine.SubscriptionSnapshot(SubUrl);
            Check(engine.Config.ProxyUri == SubUrl && engine.Config.UseProxy && engine.Strategies.Select(s => s.Profile.Id).Distinct().Count() == 3 && snapshot != null && snapshot.Links.Count == 3, "The address and the servers are saved together: " + engine.Strategies.Count);
            Check(status.Text == L.T("proxy.subscriptionKnown", 3, snapshot.Updated.ToLocalTime().ToString("g")) && save.Enabled, "The window shows how many servers there are, and Save stays available to load the list again: " + status.Text);
            Check(AppConfig.Load(Path.Combine(engine.DataDir, "zarp.json")).ProxyUri == SubUrl, "The address survives a restart");

            // повторное сохранение загружает список заново (так список обновляют); ответ без ссылок - отказ, прежний список остаётся
            var script = new ScriptedHttp { Respond = r => Text("[{\"remarks\":\"x\"}]") };
            SetPrivate(engine, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(script)));
            save.PerformClick();
            PumpUntil(() => status.Text != L.T("proxy.subscriptionLoading") && script.Requests.Count >= 2);
            Check(status.Text == L.T("proxy.subscriptionJson") && engine.Strategies.Select(s => s.Profile.Id).Distinct().Count() == 3 && engine.SubscriptionSnapshot(SubUrl).Links.Count == 3, "A JSON answer is refused with a reason and the old list stays: " + status.Text);
            link.Text = SubUrl + "&refresh=1";
            Check(status.Text == L.T("proxy.subscription", "panel.example") && save.Enabled, "Editing the address removes the old failure");
            link.Text = SubUrl;
            Check(status.Text == L.T("proxy.subscriptionJson"), "The failure belongs to the text it was for");

            script.Respond = r => new HttpResponseMessage(HttpStatusCode.Forbidden);
            save.PerformClick();
            PumpUntil(() => status.Text == L.T("proxy.subscriptionFailed", L.T("proxy.subHttp", "403")));
            Check(status.Text == L.T("proxy.subscriptionFailed", L.T("proxy.subHttp", "403")) && !status.Text.Contains("s3cr3t") && engine.Strategies.Select(s => s.Profile.Id).Distinct().Count() == 3, "A refusal of the panel is named: " + status.Text);
            script.Respond = r => Text("<!DOCTYPE html><html></html>");
            save.PerformClick();
            PumpUntil(() => status.Text == L.T("proxy.subscriptionHtml"));
            Check(status.Text == L.T("proxy.subscriptionHtml"), "A web page is named: " + status.Text);
            script.Respond = r => Text(B64("vmess://abc\nss://def"));
            save.PerformClick();
            PumpUntil(() => status.Text == L.T("proxy.subscriptionEmpty"));
            Check(status.Text == L.T("proxy.subscriptionEmpty"), "An answer without usable servers is named: " + status.Text);
            script.Respond = r => throw new HttpRequestException("down");
            save.PerformClick();
            PumpUntil(() => status.Text == L.T("proxy.subscriptionFailed", L.T("proxy.subNetwork")));
            Check(status.Text == L.T("proxy.subscriptionFailed", L.T("proxy.subNetwork")), "No network is named: " + status.Text);

            // после неудачи тот же адрес снова сохраняется удачно: отказ уходит, показан новый список
            Func<string> known = () =>
            {
                var current = engine.SubscriptionSnapshot(SubUrl);
                return current == null ? "" : L.T("proxy.subscriptionKnown", current.Links.Count, current.Updated.ToLocalTime().ToString("g"));
            };
            script.Respond = r => Text(B64(ServerLink("d.example", "Delta")));
            save.PerformClick();
            PumpUntil(() => engine.SubscriptionSnapshot(SubUrl).Links.Count == 1 && status.Text == known());
            Check(engine.SubscriptionSnapshot(SubUrl).Links.Count == 1 && status.Text == known() && save.Enabled, "After a failure the same address loads well and the failure is gone: " + status.Text);

            // адреса, которые не принимаются, и ссылки: как раньше
            link.Text = "http://panel.example/sub";
            Check(!save.Enabled && status.Text == L.T("proxy.subscriptionHttps"), "Plain http is refused with a reason: " + status.Text);
            link.Text = "https://user:pw@panel.example/sub";
            Check(!save.Enabled && status.Text == L.T("proxy.subscriptionUrl") && !status.Text.Contains("pw"), "An address with a name and a password is refused: " + status.Text);
            link.Text = "vmess://abc";
            Check(!save.Enabled && status.Text == L.T("proxy.scheme"), "Other links are refused as before: " + status.Text);
            link.Text = "trojan://secret@single.example:443#One";
            Check(save.Enabled && status.Text == "Trojan: single.example:443", "A single link is saved without any download: " + status.Text);
            save.PerformClick();
            Check(engine.Config.ProxyUri.StartsWith("trojan://") && engine.Strategies.Count > 0 && engine.Strategies.All(s => s.Profile.Host == "single.example") && !save.Enabled, "A single link replaces the subscription");
        }

        // закрытие окна во время загрузки отменяет её без ошибок и ничего не сохраняет
        var stalled = new GatedHttp();
        var engine2 = NewEngine();
        SetPrivate(engine2, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(stalled)));
        using (var form = NewForm("ConnectionForm", engine2))
        {
            PositionOffscreen(form);
            form.Show();
            Application.DoEvents();
            SetChecked(GetPrivate<Control>(form, "_useProxy"), true);
            GetPrivate<Control>(form, "_link").Text = SubUrl;
            GetPrivate<Button>(form, "_save").PerformClick();
            PumpUntil(() => stalled.Requests == 1, 5);
            Check(stalled.Requests == 1, "The load started");
        }
        PumpUntil(() => stalled.Gate.Task.IsCanceled, 5);
        Check(stalled.Gate.Task.IsCanceled && engine2.Config.ProxyUri == "" && engine2.SubscriptionSnapshot(SubUrl) == null, "Closing the window cancels the load and saves nothing");

        // ответ уже получен, а окно закрыли раньше, чем оно успело его принять: настройки не меняются.
        // В программе продолжение после загрузки ставит в очередь окно; здесь такого контекста нет, поэтому очередь своя, и тест сам решает, когда её разобрать
        var late = new GatedHttp();
        var engine3 = NewEngine();
        SetPrivate(engine3, "SubscriptionHandler", (Func<HttpMessageHandler>)(() => new NonDisposing(late)));
        var queue = new QueueingContext();
        using (var form = NewForm("ConnectionForm", engine3))
        {
            PositionOffscreen(form);
            form.Show();
            Application.DoEvents();
            SetChecked(GetPrivate<Control>(form, "_useProxy"), true);
            GetPrivate<Control>(form, "_link").Text = SubUrl;
            var before = SynchronizationContext.Current;
            SynchronizationContext.SetSynchronizationContext(queue); // Save запоминает этот контекст при первом await
            try { GetPrivate<Button>(form, "_save").PerformClick(); }
            finally { SynchronizationContext.SetSynchronizationContext(before); }
            Check(late.Requests == 1, "The load started");
            Task.Run(() => late.Gate.SetResult(Text(B64(ServerLink("a.example", "Alpha")))));
            var wait = System.Diagnostics.Stopwatch.StartNew();
            while ((engine3.SubscriptionSnapshot(SubUrl) == null || queue.Count == 0) && wait.Elapsed.TotalSeconds < 10) Thread.Sleep(5);
            Check(engine3.SubscriptionSnapshot(SubUrl) != null && queue.Count == 1, "The list arrived and its result waits for the window: " + queue.Count);
        }
        queue.Drain(); // окна уже нет, когда оно получает ответ
        Check(engine3.Config.ProxyUri == "" && !engine3.ProxyMode, "A window closed before it took the answer does not apply the settings: " + engine3.Config.ProxyUri);
    }

    /// <summary>Контекст, который складывает продолжения в очередь и отдаёт их тесту, когда он решит.</summary>
    sealed class QueueingContext : SynchronizationContext
    {
        readonly System.Collections.Concurrent.ConcurrentQueue<Tuple<SendOrPostCallback, object>> _queue = new System.Collections.Concurrent.ConcurrentQueue<Tuple<SendOrPostCallback, object>>();

        public int Count => _queue.Count;

        public override void Post(SendOrPostCallback callback, object state) => _queue.Enqueue(Tuple.Create(callback, state));

        public void Drain()
        {
            while (_queue.TryDequeue(out var item)) item.Item1(item.Item2);
        }
    }
}
