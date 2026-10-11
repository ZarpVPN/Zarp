using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Zarp.Core
{
    /// <summary>Итог проверки сервера: время первого ответа, средняя задержка или причина неудачи.</summary>
    public sealed class ProxyMeasure
    {
        public bool Ok;
        public int FirstMs;
        public int PingMs;
        /// <summary>Причина последней неудачи. Заполнена и при успехе, если какой-то из запросов не прошёл.</summary>
        public string Error;
        /// <summary>Сколько запросов не прошло.</summary>
        public int Failed;
    }

    /// <summary>
    /// Всё, что Engine делает с собственным сервером, кроме решений: узнать адрес, запустить sing-box, проверить
    /// соединение, остановить. Отдельный класс, чтобы тесты подменяли его и не запускали ни процессов, ни сети.
    /// Для серверов с XHTTP перед sing-box запускается мост Xray (sing-box такой транспорт не умеет).
    /// </summary>
    public class ProxyRuntime
    {
        public readonly SingBox Box;
        /// <summary>Мост для серверов с XHTTP. null: Xray в этой сборке нет (тесты без него), такие серверы тогда не подключаются.</summary>
        public readonly Xray Bridge;
        // последняя запущенная или подхваченная сессия идёт через мост: от этого зависит, чей журнал читать при неудаче
        bool _bridged;

        /// <summary>Страница, по которой проверяется соединение. Подменяется только в тестах: настоящая ходила бы в интернет.</summary>
        internal string TraceUrl = "https://www.cloudflare.com/cdn-cgi/trace";

        public ProxyRuntime(SingBox box, Xray bridge = null)
        {
            Box = box;
            Bridge = bridge;
        }

        /// <summary>Работает хоть что-то из наших программ (то, что надо остановить при отключении).</summary>
        public virtual bool Running => Box.Running || (Bridge != null && Bridge.Running);

        /// <summary>Вся цепочка работает: sing-box и, если сессия идёт через мост, Xray. Если жив только один из двух, подключение не работает.</summary>
        public virtual bool Intact => Box.Running && (!_bridged || (Bridge != null && Bridge.Running));

        /// <summary>sing-box работает, а нужный ему мост нет: адаптер забирает весь трафик, но отправить его некуда.</summary>
        public virtual bool BridgeLost => _bridged && Box.Running && (Bridge == null || !Bridge.Running);

        public virtual void Stop()
        {
            // сначала адаптер: пока работает только мост, трафик уже никуда не идёт
            Box.Stop();
            Bridge?.Stop();
        }

        /// <summary>Распаковать sing-box, если нужно. false - его нет ни во вшитом архиве, ни в папке данных.</summary>
        public virtual bool Prepare()
        {
            Box.ExtractEmbedded();
            return Box.Installed;
        }

        /// <summary>Распаковать Xray, если нужно (только для серверов с XHTTP). false - его нет ни во вшитом архиве, ни в папке данных.</summary>
        public virtual bool PrepareBridge()
        {
            if (Bridge == null) return false;
            Bridge.ExtractEmbedded();
            return Bridge.Installed;
        }

        static string RandomSecret()
        {
            var bytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return string.Concat(bytes.Select(b => b.ToString("x2")));
        }

        // свободный порт на 127.0.0.1, которого нет среди уже выданных этой сессии
        static int FreePort(ICollection<int> taken)
        {
            for (int attempt = 0; ; attempt++)
            {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                if (!taken.Contains(port) || attempt >= 20) { taken.Add(port); return port; }
            }
        }

        /// <summary>Заготовка сессии со свободным портом и случайными данными проверочного входа (и моста Xray, если он нужен).</summary>
        public virtual ProxySession NewSession(ProxyProfile profile)
        {
            var taken = new List<int>();
            var session = new ProxySession { Profile = profile, Port = FreePort(taken), User = "zarp", Password = RandomSecret() };
            if (profile.UsesXray)
            {
                session.XrayPort = FreePort(taken);
                session.XrayUser = "zarp";
                session.XrayPassword = RandomSecret();
                if (Bridge != null) session.XrayPath = Path.GetFullPath(Bridge.Exe);
            }
            return session;
        }

        /// <summary>
        /// IP-адрес сервера. Имя разрешается заранее системным DNS: после включения адаптера запросы пойдут в туннель,
        /// а он без адреса сервера подняться не может.
        /// </summary>
        public virtual async Task<string> ResolveAsync(string host, CancellationToken ct)
        {
            if (IPAddress.TryParse(host, out _)) return host;
            var lookup = Dns.GetHostAddressesAsync(host);
            var finished = await Task.WhenAny(lookup, Task.Delay(10000, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (finished != lookup) throw new IOException(L.T("err.proxyResolve", host));
            IPAddress[] found;
            try { found = await lookup.ConfigureAwait(false); }
            catch (SocketException) { throw new IOException(L.T("err.proxyResolve", host)); }
            var pick = found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? found.FirstOrDefault();
            if (pick == null) throw new IOException(L.T("err.proxyResolve", host));
            return pick.ToString();
        }

        /// <summary>Составить конфигурацию, проверить её и запустить sing-box (а перед ним мост Xray, если он нужен). null - всё в порядке.</summary>
        public virtual async Task<Msg> StartAsync(ProxySession session, CancellationToken ct)
        {
            string config = ProxyConfig.Build(session);
            var check = await Box.CheckAsync(config, ct).ConfigureAwait(false);
            if (!check.Ok)
                return new Msg("err.singboxConfig", Shorten(check.Output));
            _bridged = session.Profile.UsesXray;
            if (_bridged)
            {
                var bridgeError = await StartBridgeAsync(session, ct).ConfigureAwait(false);
                if (bridgeError != null) return bridgeError;
            }
            Msg err;
            try { err = await Box.StartAsync(config, session.Port, ct).ConfigureAwait(false); }
            catch { Bridge?.Stop(); throw; } // отмена посреди запуска: мост без sing-box никому не нужен
            if (err != null)
            {
                Bridge?.Stop();
                return err;
            }
            Box.SaveState(new SingBoxState { Port = session.Port, User = session.User, Password = session.Password, ProfileId = session.Profile.Id });
            return null;
        }

        async Task<Msg> StartBridgeAsync(ProxySession session, CancellationToken ct)
        {
            if (Bridge == null || !Bridge.Installed) return new Msg("err.xrayMissing");
            string config = XrayConfig.Build(session);
            var check = await Bridge.CheckAsync(config, ct).ConfigureAwait(false);
            if (!check.Ok)
                return new Msg("err.xrayConfig", ShortenXray(check.Output));
            return await Bridge.StartAsync(config, session.XrayPort, ct).ConfigureAwait(false);
        }

        static string Shorten(string text)
        {
            text = System.Text.RegularExpressions.Regex.Replace(text ?? "", "\u001b\\[[0-9;]*m", "").Replace("\r", "").Trim();
            return text.Length > 400 ? text.Substring(0, 400) + "..." : text;
        }

        /// <summary>
        /// Вывод `xray run -test`: после названия программы идёт цепочка «причина > причина > ...», и ответ в её конце.
        /// Оставляем три последних звена; имя временного файла и название версии в сообщение не попадают.
        /// </summary>
        internal static string ShortenXray(string text)
        {
            text = (text ?? "").Replace("\r", "").Trim();
            int at = text.IndexOf("Failed to start:", StringComparison.Ordinal);
            if (at >= 0) text = text.Substring(at + "Failed to start:".Length).Trim();
            var chain = text.Split(new[] { " > " }, StringSplitOptions.None);
            return Shorten(string.Join(" > ", chain.Skip(Math.Max(0, chain.Length - 3))));
        }

        /// <summary>Подхватить sing-box, оставшийся от прошлого запуска Zarp: сессия восстанавливается из файла состояния.</summary>
        public virtual ProxySession Adopt(ProxyProfile profile)
        {
            var state = Box.LoadState();
            if (state == null || state.ProfileId != profile.Id) return null;
            // без моста адаптер остался бы без сервера: такое подключение не подхватывается, Engine остановит остатки
            if (profile.UsesXray && (Bridge == null || !Bridge.Running)) return null;
            _bridged = profile.UsesXray;
            return new ProxySession { Profile = profile, Port = state.Port, User = state.User, Password = state.Password, Tun = true };
        }

        /// <summary>Дождаться, пока виртуальный адаптер Zarp появится и поднимется. false - sing-box упал или адаптера нет.</summary>
        public virtual async Task<bool> WaitAdapterAsync(CancellationToken ct)
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed.TotalSeconds < 20)
            {
                ct.ThrowIfCancellationRequested();
                if (!Box.Running) return false;
                try
                {
                    if (NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                            n.Name == SingBox.TunName && n.OperationalStatus == OperationalStatus.Up))
                        return true;
                }
                catch (NetworkInformationException) { } // адаптер как раз создаётся
                await Task.Delay(300, ct).ConfigureAwait(false);
            }
            return false;
        }

        /// <summary>
        /// Проверка уже через виртуальный адаптер: запрос от самого Zarp, без прокси, идёт по маршруту системы - то есть сквозь адаптер.
        /// Проверочный вход этого не доказывает: он ходит к серверу в обход адаптера. false - адаптер поднялся, но трафик не идёт.
        /// </summary>
        public virtual async Task<bool> CheckTunnelAsync(int timeoutMs, CancellationToken ct)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using (var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromMilliseconds(Math.Max(1000, timeoutMs)) })
                    using (var response = await http.GetAsync(TraceUrl + "?" + Guid.NewGuid().ToString("N"), ct).ConfigureAwait(false))
                        if (response.IsSuccessStatusCode) return true;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { }
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            return false;
        }

        /// <summary>
        /// Последняя строка об ошибке без метки времени и цветовых кодов (или null). С мостом сначала смотрим журнал Xray:
        /// причина обычно там, а sing-box видит от моста только оборванное соединение.
        /// </summary>
        public virtual string LastError()
        {
            try
            {
                string fromBridge = _bridged ? Bridge?.LastError() : null;
                if (fromBridge != null) return fromBridge;
                string line = Box.ReadLog().Split('\n')
                    .Select(l => System.Text.RegularExpressions.Regex.Replace(l, "\u001b\\[[0-9;]*m", ""))
                    .LastOrDefault(l => l.Contains(" ERROR ") || l.Contains(" FATAL "));
                if (line == null) return null;
                int level = Math.Max(line.IndexOf(" ERROR "), line.IndexOf(" FATAL "));
                line = line.Substring(level + 7).Trim();
                return line.Length > 300 ? line.Substring(0, 300) + "..." : line;
            }
            catch { return null; }
        }

        /// <summary>
        /// Проверка через проверочный вход sing-box: samples+1 запросов к cdn-cgi/trace, каждый на новом соединении
        /// (SOCKS5 с паролем, см. ProbeClient). Первый - прогрев, но его время считается временем подключения.
        /// Ответ должен быть настоящим трассировочным (код 200 и поле ip): страница провайдера с кодом 200 не годится.
        /// timeoutMs - срок на каждый запрос целиком.
        /// </summary>
        public virtual async Task<ProxyMeasure> MeasureAsync(ProxySession session, int samples, int timeoutMs, CancellationToken ct)
        {
            var times = new List<int>();
            int first = 0, failed = 0;
            string last = null;
            for (int i = 0; i < samples + 1; i++)
            {
                ct.ThrowIfCancellationRequested();
                var (ms, error) = await RequestAsync(session, timeoutMs, ct).ConfigureAwait(false);
                if (error != null) { last = error; failed++; continue; }
                if (first == 0) first = ms;
                if (i > 0) times.Add(ms);
            }
            if (times.Count == 0) return new ProxyMeasure { Error = last, Failed = failed };
            times.Sort();
            return new ProxyMeasure { Ok = true, FirstMs = first, PingMs = times[times.Count / 2], Error = last, Failed = failed };
        }

        /// <summary>
        /// Один запрос через проверочный вход: Ok, если пришёл настоящий ответ cdn-cgi/trace. Поиск по парам «стратегия + сервер»
        /// сначала делает его, а полный замер - только после успеха: у неработающей пары нет смысла ждать срок ещё раз на каждый запрос.
        /// </summary>
        public virtual async Task<ProxyMeasure> ProbeAsync(ProxySession session, int timeoutMs, CancellationToken ct)
        {
            var (ms, error) = await RequestAsync(session, timeoutMs, ct).ConfigureAwait(false);
            return error == null ? new ProxyMeasure { Ok = true, FirstMs = ms } : new ProxyMeasure { Error = error, Failed = 1 };
        }

        /// <summary>Запрос к cdn-cgi/trace на новом соединении: время в миллисекундах (не меньше 1) либо описание неудачи.</summary>
        async Task<(int Ms, string Error)> RequestAsync(ProxySession session, int timeoutMs, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            ProbeAnswer answer;
            try
            {
                answer = await ProbeClient.GetAsync(session.Port, session.User, session.Password,
                    new Uri(TraceUrl + "?" + Guid.NewGuid().ToString("N")), Math.Max(1000, timeoutMs), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e)
            {
                return (0, e is TimeoutException ? "timeout" : (e.InnerException ?? e).Message);
            }
            sw.Stop();
            if (answer.Status != 200) return (0, "HTTP " + answer.Status);
            if (!answer.HasIp) return (0, "trace");
            return (Math.Max(1, (int)sw.ElapsedMilliseconds), null);
        }
    }
}
