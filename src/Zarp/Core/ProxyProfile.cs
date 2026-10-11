using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace Zarp.Core
{
    public enum ProxyProtocol { Vless, Trojan, Hysteria2 }

    /// <summary>
    /// Ссылка не подходит. Message всегда "proxy.invalid": в нём нет ни куска ссылки, ни пароля. Reason - короткий код причины
    /// для подсказки в окне: "scheme", "extra", "insecure", "param:имя", "transport:имя", "security:имя" или "format".
    /// </summary>
    public sealed class ProxyLinkException : FormatException
    {
        public string Reason { get; }

        public ProxyLinkException(string reason) : base("proxy.invalid")
        {
            Reason = reason;
        }
    }

    /// <summary>
    /// Собственный сервер из одной ссылки vless://, trojan:// или hysteria2:// (hy2://). Поддерживается ровно то, что
    /// описано в документации: неизвестные параметры и транспорты отвергаются, а не отбрасываются молча.
    /// Пароль и UUID не попадают ни в имя стратегии, ни в журнал, ни в текст ошибок.
    /// </summary>
    public sealed class ProxyProfile
    {
        public ProxyProtocol Protocol { get; private set; }
        public string Host { get; private set; }
        public int Port { get; private set; }
        /// <summary>Идентификатор стратегии: от ссылки без подписи, поэтому смена любого параметра подключения сбрасывает результаты.</summary>
        public string Id { get; private set; }

        string _credential, _security, _network, _flow;
        string _sni, _alpn, _fingerprint, _publicKey, _shortId, _path, _hostHeader, _serviceName, _obfsPassword;
        bool _insecure, _obfs;
        // только XHTTP: режим, extra из ссылки как есть, поля Reality (spx, pqv), проверка сертификата TLS (pcs, vcn) и padding (x_padding_bytes)
        string _mode, _spiderX, _mldsaVerify, _pins, _certNames, _xPadding;
        Dictionary<string, object> _extra;
        // шифрованный ClientHello: ECHConfigList в base64 (ech), для любого сервера с TLS
        string _ech;

        /// <summary>
        /// Имя сервера из подписи ссылки (после #), очищенное от управляющих знаков и ограниченное по длине, или null. Нужно только
        /// для показа в списке серверов подписки; на подключение и идентификатор не влияет и секретом не считается.
        /// </summary>
        public string Label { get; private set; }

        public string Title
        {
            get
            {
                switch (Protocol)
                {
                    case ProxyProtocol.Vless: return "VLESS";
                    case ProxyProtocol.Trojan: return "Trojan";
                    default: return "Hysteria2";
                }
            }
        }

        /// <summary>Адрес для показа: host:port или [IPv6]:port.</summary>
        public string Endpoint => (Host.Contains(":") ? "[" + Host + "]" : Host) + ":" + Port.ToString(CultureInfo.InvariantCulture);

        /// <summary>
        /// Сервер как стратегия без обхода DPI: из них и стратегий zapret2 составляются пары (ServerPairs). Сама по себе она не подключается:
        /// в движке работают только пары.
        /// </summary>
        public Strategy ToStrategy() => new Strategy
        {
            Id = Id, Name = Title + ": " + Endpoint, Transport = WarpTransport.MasqueH3, Args = "", Custom = true, Profile = this,
        };

        public static bool TryParse(string text, out ProxyProfile profile)
        {
            try { profile = Parse(text); return true; }
            catch (FormatException) { profile = null; return false; }
        }

        /// <summary>Разобрать ссылку. При любой ошибке - ProxyLinkException (FormatException("proxy.invalid")) без пароля в тексте.</summary>
        public static ProxyProfile Parse(string text)
        {
            try { return ParseCore((text ?? "").Trim()); }
            catch (ProxyLinkException) { throw; }
            catch (Exception e) when (!(e is OutOfMemoryException))
            {
                // сообщения разборщиков могут содержать фрагменты ссылки, а в ней пароль
                throw new ProxyLinkException("format");
            }
        }

        /// <summary>
        /// Подсказка для окна: чем ссылка не подходит. null - ссылка годится. В тексте только то, что не секрет: имена
        /// параметров и транспортов, но не значения и не пароль.
        /// </summary>
        public static Msg Explain(string text)
        {
            try { Parse(text); return null; }
            catch (ProxyLinkException e) { return Describe(e.Reason); }
        }

        static Msg Describe(string reason)
        {
            int colon = reason.IndexOf(':');
            string kind = colon < 0 ? reason : reason.Substring(0, colon), name = colon < 0 ? "" : reason.Substring(colon + 1);
            switch (kind)
            {
                case "extra": return new Msg("proxy.extra");
                case "insecure": return new Msg("proxy.insecure");
                case "scheme": return new Msg("proxy.scheme");
                case "param": return new Msg("proxy.param", name);
                case "transport": return new Msg("proxy.transport", name);
                case "security": return new Msg("proxy.security", name);
                default: return new Msg("proxy.invalid");
            }
        }

        /// <summary>Имя из ссылки можно показать, только если оно похоже на имя (короткое, латиница, цифры), а не на кусок пароля.</summary>
        static string Token(string value) => value != null && Regex.IsMatch(value, "^[A-Za-z0-9_.-]{1,24}$") ? value : "?";

        static readonly string[] KnownParameters =
        {
            "security", "sni", "peer", "insecure", "allowInsecure", "alpn", "fp", "pbk", "sid", "flow", "encryption",
            "type", "path", "host", "serviceName", "obfs", "obfs-password",
            // только для XHTTP
            "mode", "extra", "spx", "pqv", "pcs", "vcn", "x_padding_bytes",
            // для TLS: ECH; для Reality: подсказка панелей другим клиентам
            "ech", "support-x25519mlkem768",
        };

        static readonly Regex Uuid = new Regex("^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$", RegexOptions.Compiled);
        static readonly Regex RealityKey = new Regex("^[A-Za-z0-9_-]{43}$", RegexOptions.Compiled);
        static readonly Regex HostName = new Regex("^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$", RegexOptions.Compiled);
        static readonly Regex CertName = new Regex(@"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$", RegexOptions.Compiled);
        static readonly Regex Sha256Pin = new Regex("^[a-fA-F0-9]{64}$", RegexOptions.Compiled);
        // открытый ключ ML-DSA-65 (1952 байта) в base64url без заполнения
        static readonly Regex MldsaKey = new Regex("^[A-Za-z0-9_-]{2603}$", RegexOptions.Compiled);

        static void Require(bool condition, string reason = "format")
        {
            if (!condition) throw new ProxyLinkException(reason);
        }

        static ProxyProfile ParseCore(string text)
        {
            Require(text.Length >= 1 && text.Length <= 8192);
            int schemeEnd = text.IndexOf("://", StringComparison.Ordinal);
            Require(schemeEnd > 0, "scheme");
            ProxyProtocol protocol;
            switch (text.Substring(0, schemeEnd).ToLowerInvariant())
            {
                case "vless": protocol = ProxyProtocol.Vless; break;
                case "trojan": protocol = ProxyProtocol.Trojan; break;
                case "hy2": case "hysteria2": protocol = ProxyProtocol.Hysteria2; break;
                default: throw new ProxyLinkException("scheme");
            }

            string rest = text.Substring(schemeEnd + 3);
            int hash = rest.IndexOf('#'); // имя сервера после # - только подпись
            string fragment = hash >= 0 ? rest.Substring(hash + 1) : null;
            if (hash >= 0) rest = rest.Substring(0, hash);
            string query = "";
            int question = rest.IndexOf('?');
            if (question >= 0) { query = rest.Substring(question + 1); rest = rest.Substring(0, question); }
            string path = "";
            int slash = rest.IndexOf('/');
            if (slash >= 0) { path = rest.Substring(slash); rest = rest.Substring(0, slash); }
            Require(path.Length == 0 || path == "/");

            int at = rest.LastIndexOf('@');
            Require(at > 0);
            string credential = Decode(rest.Substring(0, at));
            string authority = rest.Substring(at + 1);
            Require(credential.Length > 0 && !credential.Any(char.IsControl));

            string host, portText = "";
            if (authority.StartsWith("["))
            {
                int close = authority.IndexOf(']');
                Require(close > 1);
                host = authority.Substring(1, close - 1);
                string after = authority.Substring(close + 1);
                Require(after.Length == 0 || after[0] == ':');
                if (after.Length > 0) portText = after.Substring(1);
                Require(IPAddress.TryParse(host, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6);
            }
            else
            {
                int colon = authority.IndexOf(':');
                host = colon < 0 ? authority : authority.Substring(0, colon);
                if (colon >= 0) portText = authority.Substring(colon + 1);
                Require(host.Length > 0 && host.Length <= 253 && HostName.IsMatch(host));
            }
            Require(host.IndexOf('%') < 0);
            int port;
            if (portText.Length == 0) { Require(protocol == ProxyProtocol.Hysteria2); port = 443; }
            else
            {
                Require(portText.Length <= 5 && portText.All(c => c >= '0' && c <= '9'));
                port = int.Parse(portText, CultureInfo.InvariantCulture);
            }
            Require(port >= 1 && port <= 65535);

            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var piece in query.Split('&'))
            {
                if (piece.Length == 0) continue;
                int eq = piece.IndexOf('=');
                string key = Decode(eq < 0 ? piece : piece.Substring(0, eq));
                string value = eq < 0 ? "" : Decode(piece.Substring(eq + 1));
                Require(!parameters.ContainsKey(key));
                parameters[key] = value;
            }
            string Get(string key) => parameters.TryGetValue(key, out var v) ? v : null;

            foreach (var key in parameters.Keys)
                Require(KnownParameters.Contains(key), "param:" + Token(key));

            Require(Get("encryption") == null || Get("encryption") == "" || Get("encryption") == "none", "param:encryption");
            string security = Get("security") ?? (protocol == ProxyProtocol.Vless ? "none" : "tls");
            Require(security == "none" || security == "tls" || security == "reality", "security:" + Token(security));
            Require(protocol == ProxyProtocol.Vless || security == "tls");
            string network = Get("type") ?? "tcp";
            bool xhttp = network == "xhttp";
            Require(network == "tcp" || network == "ws" || network == "grpc" || network == "httpupgrade" || xhttp, "transport:" + Token(network));
            Require(protocol != ProxyProtocol.Hysteria2 || network == "tcp", "transport:" + Token(network));
            Require(!xhttp || protocol == ProxyProtocol.Vless, "transport:" + network);
            // эти параметры что-то значат только для XHTTP (sing-box их не знает): молча отбрасывать их нельзя
            string Filled(string key) => string.IsNullOrWhiteSpace(Get(key)) ? null : Get(key);
            foreach (var key in new[] { "mode", "extra" }) Require(xhttp || Filled(key) == null, "param:" + key);
            foreach (var key in new[] { "spx", "pqv" }) Require((xhttp && security == "reality") || Filled(key) == null, "param:" + key);
            foreach (var key in new[] { "pcs", "vcn" }) Require((xhttp && security == "tls") || Filled(key) == null, "param:" + key);
            Require(xhttp || Filled("x_padding_bytes") == null, "param:x_padding_bytes");
            // ECH шифрует имя сервера в рукопожатии TLS; у Reality и у соединения без TLS его нет
            Require(security == "tls" || Filled("ech") == null, "param:ech");
            // «support-x25519mlkem768» - подсказка панели (3x-ui) другим клиентам, Mihomo: предлагать гибридный обмен ключами в Reality.
            // В Xray это не настройка (обмен ключами выбирает отпечаток), поэтому параметр принимается и ничего не меняет
            Require(security == "reality" || Filled("support-x25519mlkem768") == null, "param:support-x25519mlkem768");
            string mlkem = Filled("support-x25519mlkem768");
            Require(mlkem == null || mlkem == "true" || mlkem == "false" || mlkem == "1" || mlkem == "0");
            string flow = Get("flow") ?? "";
            Require(flow == "" || flow == "xtls-rprx-vision", "param:flow");
            Require(flow.Length == 0 || (protocol == ProxyProtocol.Vless && network == "tcp" && security != "none"));
            if (protocol == ProxyProtocol.Vless) Require(Uuid.IsMatch(credential));
            foreach (var key in new[] { "insecure", "allowInsecure" })
            {
                string flag = Get(key);
                Require(flag == null || flag == "0" || flag == "1" || flag == "true" || flag == "false");
            }
            bool insecure = new[] { Get("insecure"), Get("allowInsecure") }.Any(v => v == "1" || v == "true");
            // Xray убрал allowInsecure: сертификат сервера XHTTP проверяется всегда, а доверять самоподписанному можно по хешу (pcs)
            Require(!(xhttp && insecure), "insecure");

            var profile = new ProxyProfile
            {
                Protocol = protocol, Host = host, Port = port,
                _credential = credential, _security = security, _network = network, _flow = flow,
                _sni = Get("sni") ?? Get("peer") ?? host,
                _insecure = insecure,
                _alpn = string.IsNullOrWhiteSpace(Get("alpn")) ? null : Get("alpn"),
                _fingerprint = Get("fp"),
                _path = Get("path") ?? "/", _hostHeader = Get("host"), _serviceName = Get("serviceName") ?? "",
            };
            if (xhttp) ParseXhttp(profile, security, Filled);
            if (Filled("ech") != null) profile._ech = NormalizeEch(Filled("ech"));
            if (Filled("x_padding_bytes") != null) profile._xPadding = ValidatePadding(Filled("x_padding_bytes"));
            profile.Label = fragment == null ? null : CleanLabel(fragment);
            if (security == "reality")
            {
                string key = Get("pbk");
                Require(key != null && RealityKey.IsMatch(key));
                string shortId = Get("sid") ?? "";
                Require(shortId.Length <= 16 && shortId.Length % 2 == 0 && shortId.All(Uri.IsHexDigit));
                profile._publicKey = key;
                profile._shortId = shortId;
            }
            string obfs = Get("obfs");
            if (obfs != null)
            {
                Require(protocol == ProxyProtocol.Hysteria2 && obfs == "salamander");
                string password = Get("obfs-password");
                Require(!string.IsNullOrEmpty(password));
                profile._obfs = true;
                profile._obfsPassword = password;
            }
            // подпись после # (имя сервера) на подключение не влияет, поэтому в идентификатор не входит
            int label = text.IndexOf('#');
            using (var sha = SHA256.Create())
                profile.Id = "proxy-" + string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes(label >= 0 ? text.Substring(0, label) : text)).Take(12).Select(b => b.ToString("x2")));
            return profile;
        }

        /// <summary>Подпись из ссылки (после #) для показа: без управляющих знаков и лишних пробелов, не длиннее 64 знаков. Битая подпись не делает ссылку негодной.</summary>
        static string CleanLabel(string fragment)
        {
            try
            {
                string text = Uri.UnescapeDataString(fragment);
                text = Regex.Replace(new string(text.Where(c => !char.IsControl(c)).ToArray()), @"\s+", " ").Trim();
                if (text.Length > 64) text = text.Substring(0, 64).TrimEnd();
                return text.Length == 0 ? null : text;
            }
            catch (Exception) { return null; }
        }

        /// <summary>
        /// ECHConfigList из ссылки (base64, допускается и вариант с - и _): список с двухбайтной длиной в начале. Возвращает каноническую запись
        /// base64. Остальное (версия, ключи) проверит сама программа: sing-box или Xray.
        /// </summary>
        static string NormalizeEch(string value)
        {
            string text = Regex.Replace(value, @"\s+", "").TrimEnd('=').Replace('-', '+').Replace('_', '/');
            Require(text.Length <= 4096 && Regex.IsMatch(text, "^[A-Za-z0-9+/]+$"));
            Require(text.Length % 4 != 1);
            byte[] bytes;
            try { bytes = Convert.FromBase64String(text + new string('=', (4 - text.Length % 4) % 4)); }
            catch (FormatException) { throw new ProxyLinkException("format"); }
            Require(bytes.Length >= 6 && ((bytes[0] << 8) | bytes[1]) == bytes.Length - 2);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>Размер padding XHTTP: число или диапазон «от-до» (так его пишут панели в x_padding_bytes).</summary>
        static string ValidatePadding(string value)
        {
            var m = Regex.Match(value.Trim(), @"^([1-9][0-9]{0,5})(?:-([1-9][0-9]{0,5}))?$");
            Require(m.Success);
            if (m.Groups[2].Success)
                Require(int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) <= int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture));
            return m.Value;
        }

        /// <summary>Параметры, которые есть только у XHTTP: режим, extra, поля Reality и проверка сертификата. Значения проверяются здесь, остальное проверит сам Xray.</summary>
        static void ParseXhttp(ProxyProfile profile, string security, Func<string, string> filled)
        {
            string mode = filled("mode") ?? "auto";
            Require(mode == "auto" || mode == "packet-up" || mode == "stream-up" || mode == "stream-one");
            profile._mode = mode;

            string extra = filled("extra");
            if (extra != null)
            {
                Dictionary<string, object> map;
                try { map = new JavaScriptSerializer().DeserializeObject(extra) as Dictionary<string, object>; }
                catch (Exception) { map = null; }
                Require(map != null, "extra");
                profile._extra = map.Count > 0 ? map : null;
            }

            if (security == "reality")
            {
                string spx = filled("spx");
                if (spx != null)
                {
                    Require(spx.Length <= 256 && spx[0] == '/' && !spx.Any(char.IsControl));
                    profile._spiderX = spx;
                }
                string pqv = filled("pqv");
                if (pqv != null)
                {
                    Require(MldsaKey.IsMatch(pqv));
                    profile._mldsaVerify = pqv;
                }
            }
            else if (security == "tls")
            {
                string pcs = filled("pcs");
                if (pcs != null)
                {
                    // отпечаток можно записать и как в OpenSSL (с двоеточиями); в Xray он уходит строкой из hex через запятую
                    var pins = pcs.Split(',').Select(p => p.Trim().Replace(":", "")).Where(p => p.Length > 0).ToList();
                    Require(pins.Count >= 1 && pins.Count <= 8 && pins.All(Sha256Pin.IsMatch));
                    profile._pins = string.Join(",", pins.Select(p => p.ToLowerInvariant()));
                }
                string vcn = filled("vcn");
                if (vcn != null)
                {
                    var names = vcn.Split(',').Select(n => n.Trim()).Where(n => n.Length > 0).ToList();
                    Require(names.Count >= 1 && names.Count <= 8 && names.All(n => n.Length <= 253 && CertName.IsMatch(n)));
                    profile._certNames = string.Join(",", names);
                }
            }
        }

        /// <summary>Как URLDecoder, но «+» остаётся плюсом: так пароли с + не портятся. Битый %-код - ошибка.</summary>
        static string Decode(string value)
        {
            for (int i = 0; i < value.Length; i++)
                if (value[i] == '%')
                    Require(i + 2 < value.Length && Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]));
            return Uri.UnescapeDataString(value);
        }

        /// <summary>ECHConfigList в виде строк PEM, как её читает sing-box: BEGIN ECH CONFIGS, base64 по 64 знака, END ECH CONFIGS.</summary>
        static List<string> EchPem(string base64)
        {
            var lines = new List<string> { "-----BEGIN ECH CONFIGS-----" };
            for (int i = 0; i < base64.Length; i += 64) lines.Add(base64.Substring(i, Math.Min(64, base64.Length - i)));
            lines.Add("-----END ECH CONFIGS-----");
            return lines;
        }

        /// <summary>
        /// Исходящее подключение sing-box с тегом «proxy». address - адрес, на который реально идёт соединение
        /// (обычно уже разрешённый IP сервера); имя в TLS (SNI) остаётся тем, что указано в ссылке.
        /// </summary>
        public Dictionary<string, object> BuildOutbound(string address = null)
        {
            if (UsesXray) throw new InvalidOperationException("XHTTP is served by the Xray bridge, not by sing-box");
            var o = new Dictionary<string, object>
            {
                ["type"] = Protocol == ProxyProtocol.Vless ? "vless" : Protocol == ProxyProtocol.Trojan ? "trojan" : "hysteria2",
                ["tag"] = "proxy",
                ["server"] = address ?? Host,
                ["server_port"] = Port,
                ["domain_resolver"] = "bootstrap",
                ["connect_timeout"] = "15s",
            };
            if (Protocol == ProxyProtocol.Vless)
            {
                o["uuid"] = _credential;
                o["flow"] = _flow;
                o["packet_encoding"] = "xudp";
            }
            else o["password"] = _credential;

            if (_security != "none")
            {
                var tls = new Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = _sni,
                    ["insecure"] = _insecure,
                };
                if (_alpn != null) tls["alpn"] = _alpn.Split(',').Select(a => a.Trim()).Where(a => a.Length > 0).ToList();
                // ECH sing-box берёт в PEM; с ним работает стандартный TLS, отпечаток uTLS там не применяется, поэтому его не просим
                if (_ech != null) tls["ech"] = new Dictionary<string, object> { ["enabled"] = true, ["config"] = EchPem(_ech) };
                if (Protocol != ProxyProtocol.Hysteria2 && _ech == null && (_fingerprint != null || _security == "reality"))
                    tls["utls"] = new Dictionary<string, object> { ["enabled"] = true, ["fingerprint"] = _fingerprint ?? "chrome" };
                if (_security == "reality")
                    tls["reality"] = new Dictionary<string, object> { ["enabled"] = true, ["public_key"] = _publicKey, ["short_id"] = _shortId };
                o["tls"] = tls;
            }
            if (_network != "tcp")
            {
                var transport = new Dictionary<string, object> { ["type"] = _network };
                if (_network == "grpc") transport["service_name"] = _serviceName;
                else
                {
                    transport["path"] = _path;
                    if (_hostHeader != null)
                    {
                        if (_network == "ws") transport["headers"] = new Dictionary<string, object> { ["Host"] = _hostHeader };
                        else transport["host"] = _hostHeader;
                    }
                }
                o["transport"] = transport;
            }
            if (_obfs)
                o["obfs"] = new Dictionary<string, object> { ["type"] = "salamander", ["password"] = _obfsPassword };
            return o;
        }

        /// <summary>sing-box не умеет XHTTP: такой сервер подключается через мост Xray (см. Xray и XrayConfig).</summary>
        public bool UsesXray => _network == "xhttp";

        /// <summary>Соединение с сервером может идти по QUIC (UDP): Hysteria2 или ALPN h3. Нужно ручному тесту, который видит только TCP.</summary>
        public bool UsesQuic => Protocol == ProxyProtocol.Hysteria2 || (_alpn != null && _alpn.Split(',').Any(a => a.Trim() == "h3"));

        /// <summary>
        /// Транспорт соединения с сервером глазами zapret2: QUIC (Hysteria2 и XHTTP, у которого ALPN только h3) похож на MASQUE по
        /// HTTP/3, TLS по TCP - на MASQUE по HTTP/2. От него зависит, какие стратегии подходят серверу и какой фильтр WinDivert строится.
        /// </summary>
        public WarpTransport OuterTransport =>
            Protocol == ProxyProtocol.Hysteria2 || (UsesXray && _alpn != null && _alpn.Split(',').Select(a => a.Trim()).Where(a => a.Length > 0).SequenceEqual(new[] { "h3" }))
                ? WarpTransport.MasqueH3 : WarpTransport.MasqueH2;

        /// <summary>
        /// Исходящее подключение sing-box с тегом «proxy» для серверов с XHTTP: SOCKS5 с паролем к мосту Xray на 127.0.0.1.
        /// Мост запущен только на время сессии, а порт и пароль у каждой сессии свои.
        /// </summary>
        public static Dictionary<string, object> BuildBridgeOutbound(int port, string user, string password) => new Dictionary<string, object>
        {
            ["type"] = "socks",
            ["tag"] = "proxy",
            ["server"] = "127.0.0.1",
            ["server_port"] = port,
            ["version"] = "5",
            ["username"] = user,
            ["password"] = password,
        };

        /// <summary>
        /// Исходящее подключение Xray (VLESS поверх XHTTP) с тегом «server». address - адрес, на который реально идёт соединение
        /// (обычно уже разрешённый IP сервера); имя в TLS (SNI) остаётся тем, что указано в ссылке.
        /// </summary>
        public Dictionary<string, object> BuildXrayOutbound(string address = null)
        {
            if (!UsesXray) throw new InvalidOperationException("Not an XHTTP profile");
            var xhttp = new Dictionary<string, object>
            {
                ["path"] = string.IsNullOrEmpty(_path) ? "/" : _path,
                ["mode"] = _mode,
            };
            // Host запроса: из ссылки; без TLS и без host в ссылке им был бы IP-адрес вместо имени сервера
            if (!string.IsNullOrEmpty(_hostHeader)) xhttp["host"] = _hostHeader;
            else if (_security == "none" && !IPAddress.TryParse(Host, out _)) xhttp["host"] = Host;
            // extra заменяет остальные настройки XHTTP целиком (кроме host, path и mode): Xray так и читает ссылки
            if (_extra != null) xhttp["extra"] = _extra;
            // x_padding_bytes панели пишут для клиентов на sing-box, а те же числа кладут и в extra; без extra он единственный источник
            else if (_xPadding != null) xhttp["xPaddingBytes"] = _xPadding;

            var stream = new Dictionary<string, object> { ["network"] = "xhttp", ["security"] = _security, ["xhttpSettings"] = xhttp };
            if (_security == "tls")
            {
                var tls = new Dictionary<string, object> { ["serverName"] = _sni };
                if (_alpn != null) tls["alpn"] = _alpn.Split(',').Select(a => a.Trim()).Where(a => a.Length > 0).ToList();
                if (_fingerprint != null) tls["fingerprint"] = _fingerprint;
                if (_pins != null) tls["pinnedPeerCertSha256"] = _pins;
                // с 26.5 Xray требует ECH, если он задан (echForceQuery убран): сервер без ECH такому клиенту не подходит
                if (_ech != null) tls["echConfigList"] = _ech;
                if (_certNames != null) tls["verifyPeerCertByName"] = _certNames;
                stream["tlsSettings"] = tls;
            }
            else if (_security == "reality")
            {
                var reality = new Dictionary<string, object>
                {
                    ["serverName"] = _sni,
                    ["fingerprint"] = _fingerprint ?? "chrome",
                    ["publicKey"] = _publicKey,
                    ["shortId"] = _shortId,
                };
                if (_spiderX != null) reality["spiderX"] = _spiderX;
                if (_mldsaVerify != null) reality["mldsa65Verify"] = _mldsaVerify;
                stream["realitySettings"] = reality;
            }

            var user = new Dictionary<string, object> { ["id"] = _credential, ["encryption"] = "none", ["flow"] = "" };
            return new Dictionary<string, object>
            {
                ["tag"] = "server",
                ["protocol"] = "vless",
                ["settings"] = new Dictionary<string, object>
                {
                    ["vnext"] = new List<object>
                    {
                        new Dictionary<string, object>
                        {
                            ["address"] = address ?? Host,
                            ["port"] = Port,
                            ["users"] = new List<object> { user },
                        },
                    },
                },
                ["streamSettings"] = stream,
            };
        }
    }
}
