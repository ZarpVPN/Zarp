using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace Zarp.Core
{
    /// <summary>
    /// Сборка конфигурации Xray: SOCKS5-вход с паролем на 127.0.0.1 (мост) и одно исходящее подключение к серверу по VLESS
    /// поверх XHTTP. Ни маршрутизации, ни DNS, ни баз GeoIP в ней нет: всем этим занимается sing-box. Конфигурацию целиком
    /// составляет Zarp, чужая не принимается.
    /// </summary>
    public static class XrayConfig
    {
        static Dictionary<string, object> Obj(params object[] pairs)
        {
            var d = new Dictionary<string, object>();
            for (int i = 0; i < pairs.Length; i += 2) d[(string)pairs[i]] = pairs[i + 1];
            return d;
        }

        public static string Build(ProxySession s)
        {
            if (!s.Profile.UsesXray) throw new InvalidOperationException("Not an XHTTP profile");
            if (s.XrayPort <= 0 || string.IsNullOrEmpty(s.XrayUser) || string.IsNullOrEmpty(s.XrayPassword))
                throw new InvalidOperationException("The Xray bridge needs a port and a login");
            var config = Obj(
                // Журнал обращений (access) по умолчанию пишет адреса, куда ходит пользователь: он выключен. Ошибки подключения Xray
                // пишет на уровне info, а на нём в журнал попадают и адреса назначения. Поэтому подробно - только при проверке
                // сервера без адаптера, где единственный запрос это проверочный; в сессии с адаптером остаются предупреждения.
                "log", Obj("loglevel", s.Tun ? "warning" : "info", "access", "none"),
                "inbounds", new List<object>
                {
                    Obj("tag", "bridge", "listen", "127.0.0.1", "port", s.XrayPort, "protocol", "socks",
                        // Xray 26.5 переименовал accounts в users (старое имя ещё читается, но новое - то, что описано в документации)
                        "settings", Obj("auth", "password", "udp", true, "ip", "127.0.0.1",
                            "users", new List<object> { Obj("user", s.XrayUser, "pass", s.XrayPassword) })),
                },
                "outbounds", new List<object> { s.Profile.BuildXrayOutbound(s.Address) });
            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(config);
        }
    }
}
