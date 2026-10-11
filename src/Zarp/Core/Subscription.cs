using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Zarp.Core
{
    /// <summary>Что вставлено в поле сервера: одна ссылка, адрес подписки или ничего подходящего.</summary>
    public enum ProxySourceKind { None, Link, Subscription }

    /// <summary>Одно поле «свой сервер»: ссылка vless://, trojan://, hysteria2:// либо https-адрес подписки (список таких ссылок).</summary>
    public static class ProxySource
    {
        public static ProxySourceKind Kind(string text)
        {
            text = (text ?? "").Trim();
            if (Subscription.IsUrl(text)) return ProxySourceKind.Subscription;
            return ProxyProfile.TryParse(text, out _) ? ProxySourceKind.Link : ProxySourceKind.None;
        }

        /// <summary>Чем текст не подходит (null - подходит). Ссылку разбирает ProxyProfile; адреса http:// и негодные https:// называются отдельно.</summary>
        public static Msg Explain(string text)
        {
            text = (text ?? "").Trim();
            if (Subscription.IsUrl(text)) return null;
            if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return new Msg("proxy.subscriptionHttps");
            if (text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return new Msg("proxy.subscriptionUrl");
            return ProxyProfile.Explain(text);
        }
    }

    /// <summary>Сервер из подписки: ссылка как есть и её разбор.</summary>
    public sealed class SubscriptionEntry
    {
        public string Link;
        public ProxyProfile Profile;
    }

    /// <summary>Итог разбора ответа подписки.</summary>
    public sealed class SubscriptionResult
    {
        public readonly List<SubscriptionEntry> Servers = new List<SubscriptionEntry>();
        /// <summary>Строки с другими схемами (vmess://, ss://, tuic:// и так далее) и мусор: Zarp их не поддерживает.</summary>
        public int Unsupported;
        /// <summary>Ссылки vless://, trojan://, hysteria2://, которые Zarp разобрать не смог (неизвестный параметр, неверное значение).</summary>
        public int Refused;
        /// <summary>Серверов больше, чем Zarp берёт: лишние отброшены.</summary>
        public int Truncated;
        /// <summary>Ответ - JSON, а не список ссылок.</summary>
        public bool Json;
        /// <summary>Ответ - веб-страница (панель приняла запрос за запрос браузера или адрес не тот).</summary>
        public bool Html;
    }

    /// <summary>Подписку не удалось загрузить. Reason - короткий код без адреса и токена: "http:403", "timeout", "network", "tls", "big", "redirect", "empty".</summary>
    public sealed class SubscriptionException : Exception
    {
        public string Reason { get; }

        public SubscriptionException(string reason) : base("subscription: " + reason)
        {
            Reason = reason;
        }

        /// <summary>Причина для показа пользователю на его языке.</summary>
        public Msg Describe()
        {
            if (Reason.StartsWith("http:", StringComparison.Ordinal)) return new Msg("proxy.subHttp", Reason.Substring(5));
            switch (Reason)
            {
                case "timeout": return new Msg("proxy.subTimeout");
                case "tls": return new Msg("proxy.subTls");
                case "big": return new Msg("proxy.subBig");
                case "redirect": return new Msg("proxy.subRedirect");
                case "empty": return new Msg("proxy.subEmpty");
                default: return new Msg("proxy.subNetwork");
            }
        }
    }

    /// <summary>
    /// Подписка: https-адрес, который отдаёт список ссылок на серверы (base64 или обычным текстом, по ссылке в строке). Так их выдают
    /// панели вроде 3x-ui. Адрес содержит токен доступа, поэтому ни в журнал, ни в сообщения он не попадает. Загружается только по
    /// HTTPS, с проверкой сертификата.
    /// </summary>
    public static class Subscription
    {
        public const int MaxBytes = 2 << 20;
        public const int MaxServers = 200;
        const int MaxRedirects = 5;
        /// <summary>Сколько длится весь запрос вместе с чтением ответа. Не const только ради тестов: они проверяют срок, не дожидаясь 25 секунд.</summary>
        internal static TimeSpan Deadline = TimeSpan.FromSeconds(25);

        /// <summary>Какими клиентами представляемся: сначала собой, потом общепринятым именем клиента, если панель ответила не списком ссылок.</summary>
        public static readonly string[] UserAgents = { "Zarp/1.0", "v2rayN/7.0" };

        /// <summary>Адрес подписки: те же правила, что у источников баз GeoIP (только HTTPS, без имени и пароля, без #).</summary>
        public static bool IsUrl(string text) => RoutingSettings.ValidSource((text ?? "").Trim());

        /// <summary>Имя сайта из адреса для показа (токен в адресе остаётся скрытым).</summary>
        public static string HostOf(string url)
        {
            Uri uri;
            return Uri.TryCreate((url ?? "").Trim(), UriKind.Absolute, out uri) ? uri.Host : "";
        }

        // ------------------------------------------------------------------ разбор

        static readonly Regex LinkLine = new Regex(@"^[A-Za-z][A-Za-z0-9+.\-]*://", RegexOptions.Compiled);

        /// <summary>Ответ панели в текст со ссылками: base64 (обычный и URL-безопасный, с заполнением и без) или сам текст.</summary>
        static string DecodeBody(string body)
        {
            string text = (body ?? "").TrimStart('\uFEFF').Trim();
            if (text.Split('\n').Any(l => LinkLine.IsMatch(l.Trim()))) return text;
            string compact = Regex.Replace(text, @"\s+", "").TrimEnd('=').Replace('-', '+').Replace('_', '/');
            if (compact.Length < 8 || compact.Length % 4 == 1 || !Regex.IsMatch(compact, "^[A-Za-z0-9+/]+$")) return text;
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(compact + new string('=', (4 - compact.Length % 4) % 4))).TrimStart('\uFEFF');
                return decoded.Contains("://") || decoded.TrimStart().StartsWith("{") || decoded.TrimStart().StartsWith("[") ? decoded : text;
            }
            catch (FormatException) { return text; }
        }

        /// <summary>Разобрать ответ подписки. Ссылки, которые Zarp не поддерживает, не теряются молча: они посчитаны.</summary>
        public static SubscriptionResult Parse(string body)
        {
            var result = new SubscriptionResult();
            string text = DecodeBody(body);
            string trimmed = text.TrimStart();
            if (trimmed.StartsWith("{") || trimmed.StartsWith("["))
            {
                result.Json = true;
                return result;
            }
            if (trimmed.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase))
            {
                result.Html = true;
                return result;
            }
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var raw in text.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == '#') continue;
                int scheme = line.IndexOf("://", StringComparison.Ordinal);
                if (scheme <= 0 || !LinkLine.IsMatch(line)) { result.Unsupported++; continue; }
                string name = line.Substring(0, scheme).ToLowerInvariant();
                if (name != "vless" && name != "trojan" && name != "hysteria2" && name != "hy2") { result.Unsupported++; continue; }
                ProxyProfile profile;
                if (!ProxyProfile.TryParse(line, out profile)) { result.Refused++; continue; }
                if (!seen.Add(profile.Id)) continue; // та же ссылка дважды
                if (result.Servers.Count >= MaxServers) { result.Truncated++; continue; }
                result.Servers.Add(new SubscriptionEntry { Link = line, Profile = profile });
            }
            return result;
        }

        /// <summary>
        /// Стратегии-серверы для списка. Имя - подпись из ссылки (так серверы узнаются в панели), без подписи - протокол и адрес;
        /// одинаковые подписи различаются адресом.
        /// </summary>
        public static List<Strategy> ToStrategies(IEnumerable<ProxyProfile> profiles)
        {
            var list = profiles.ToList();
            var names = list.Select(p => p.Label ?? p.Title + ": " + p.Endpoint).ToList();
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<Strategy>();
            for (int i = 0; i < list.Count; i++)
            {
                string name = names[i];
                if (names.Count(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)) > 1) name += " [" + list[i].Endpoint + "]";
                string unique = name;
                for (int n = 2; !used.Add(unique); n++) unique = name + " #" + n.ToString(CultureInfo.InvariantCulture);
                var strategy = list[i].ToStrategy();
                strategy.Name = unique;
                result.Add(strategy);
            }
            return result;
        }

        // ------------------------------------------------------------------ загрузка

        /// <summary>Обработчик HTTP по умолчанию. Тесты подставляют свой (handlerFactory), чтобы загрузка не ходила в сеть.</summary>
        public static HttpMessageHandler NewHandler() => new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false,
            // только gzip: «deflate» .NET Framework читает как сырой поток, а серверы по стандарту шлют его в обёртке zlib, и такой ответ не читается
            AutomaticDecompression = DecompressionMethods.GZip,
        };

        /// <summary>
        /// Скачать ответ подписки. Переходы обрабатываются вручную (не более 5, каждый адрес - HTTPS без имени и пароля), ответ не больше 2 МБ,
        /// весь запрос не дольше 25 секунд. Ошибки - SubscriptionException без адреса и токена.
        /// </summary>
        public static async Task<string> DownloadAsync(string url, Func<HttpMessageHandler> handlerFactory, string userAgent, CancellationToken ct)
        {
            using (var limit = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                limit.CancelAfter(Deadline);
                try
                {
                    using (var http = new HttpClient((handlerFactory ?? NewHandler)(), true) { Timeout = System.Threading.Timeout.InfiniteTimeSpan })
                    {
                        http.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
                        http.DefaultRequestHeaders.Accept.ParseAdd("*/*");
                        string current = url.Trim();
                        for (int hop = 0; hop <= MaxRedirects; hop++)
                        {
                            if (!RoutingSettings.ValidSource(current)) throw new SubscriptionException("redirect");
                            using (var response = await http.GetAsync(current, HttpCompletionOption.ResponseHeadersRead, limit.Token).ConfigureAwait(false))
                            {
                                int code = (int)response.StatusCode;
                                if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308)
                                {
                                    var location = response.Headers.Location;
                                    if (location == null) throw new SubscriptionException("redirect");
                                    current = new Uri(new Uri(current), location).ToString();
                                    continue;
                                }
                                if (code != 200) throw new SubscriptionException("http:" + code.ToString(CultureInfo.InvariantCulture));
                                long? length = response.Content.Headers.ContentLength;
                                if (length.HasValue && length.Value > MaxBytes) throw new SubscriptionException("big");
                                using (limit.Token.Register(response.Dispose)) // зависшее чтение прерывается закрытием ответа
                                using (var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                                using (var buffer = new MemoryStream())
                                {
                                    var chunk = new byte[16 * 1024];
                                    int n;
                                    while ((n = await input.ReadAsync(chunk, 0, chunk.Length, limit.Token).ConfigureAwait(false)) > 0)
                                    {
                                        buffer.Write(chunk, 0, n);
                                        if (buffer.Length > MaxBytes) throw new SubscriptionException("big");
                                    }
                                    if (buffer.Length == 0) throw new SubscriptionException("empty");
                                    return Encoding.UTF8.GetString(buffer.ToArray());
                                }
                            }
                        }
                        throw new SubscriptionException("redirect");
                    }
                }
                catch (SubscriptionException) { throw; }
                catch (Exception e)
                {
                    // у исключений сети в тексте бывает адрес со служебными параметрами: наружу идёт только причина
                    if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
                    if (e is OperationCanceledException || e is ObjectDisposedException || e is TimeoutException) throw new SubscriptionException("timeout");
                    var web = e as WebException ?? e.InnerException as WebException ?? e.InnerException?.InnerException as WebException;
                    if (web != null && (web.Status == WebExceptionStatus.TrustFailure || web.Status == WebExceptionStatus.SecureChannelFailure)) throw new SubscriptionException("tls");
                    if (e is System.Security.Authentication.AuthenticationException || e.InnerException is System.Security.Authentication.AuthenticationException) throw new SubscriptionException("tls");
                    throw new SubscriptionException("network");
                }
            }
        }

        /// <summary>
        /// Загрузить и разобрать подписку. Если панель ответила не списком ссылок, один раз пробуем под именем распространённого клиента:
        /// панели выбирают формат ответа по User-Agent. Ошибка загрузки второй попытки не вызывает.
        /// </summary>
        public static async Task<SubscriptionResult> LoadAsync(string url, Func<HttpMessageHandler> handlerFactory, CancellationToken ct)
        {
            SubscriptionResult first = null;
            foreach (var agent in UserAgents)
            {
                SubscriptionResult result;
                try { result = Parse(await DownloadAsync(url, handlerFactory, agent, ct).ConfigureAwait(false)); }
                catch (SubscriptionException) when (first != null) { return first; } // вторая попытка не удалась: остаётся ответ первой
                if (first == null) first = result;
                if (result.Servers.Count > 0) return result;
            }
            return first;
        }
    }

    /// <summary>
    /// Последний список серверов подписки на диске: по нему работают программа без сети и перезапуск. В файле ссылки (в них секреты,
    /// как и в настройках), а адрес подписки - только хешем: файл относится к тому адресу, для которого сохранён.
    /// </summary>
    public sealed class SubscriptionCache
    {
        public sealed class Snapshot
        {
            public List<string> Links = new List<string>();
            public DateTime Updated;
        }

        readonly string _file;

        public SubscriptionCache(string file)
        {
            _file = file;
        }

        static string Hash(string url)
        {
            using (var sha = SHA256.Create())
                return string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes((url ?? "").Trim())).Select(b => b.ToString("x2")));
        }

        public void Save(string url, IEnumerable<string> links, DateTime updatedUtc)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_file));
            var data = new Dictionary<string, object>
            {
                ["source"] = Hash(url),
                ["updated"] = updatedUtc.ToString("o", CultureInfo.InvariantCulture),
                ["links"] = links.ToList(),
            };
            string temp = _file + ".tmp";
            File.WriteAllText(temp, new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(data), new UTF8Encoding(false));
            if (File.Exists(_file)) File.Replace(temp, _file, null);
            else File.Move(temp, _file);
        }

        /// <summary>Сохранённый список для этого адреса или null: файла нет, он испорчен или сохранён для другого адреса.</summary>
        public Snapshot Load(string url)
        {
            try
            {
                var data = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(File.ReadAllText(_file, Encoding.UTF8)) as Dictionary<string, object>;
                if (data == null || !(data["source"] is string source) || source != Hash(url)) return null;
                var snapshot = new Snapshot
                {
                    Updated = DateTime.Parse((string)data["updated"], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime(),
                };
                foreach (var item in (System.Collections.IEnumerable)data["links"])
                    if (item is string link) snapshot.Links.Add(link);
                return snapshot;
            }
            catch (Exception) { return null; }
        }

        public void Delete()
        {
            try { File.Delete(_file); } catch { }
        }
    }
}
