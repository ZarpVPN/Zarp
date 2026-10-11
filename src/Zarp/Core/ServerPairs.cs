using System;
using System.Collections.Generic;
using System.Linq;

namespace Zarp.Core
{
    /// <summary>
    /// Режим «свой сервер» - это zapret2 плюс конкретный эндпоинт: сервер (VLESS, Trojan, Hysteria2, XHTTP) и стратегия, которая
    /// проводит соединение с ним через DPI. Стратегия этого режима - пара (стратегия zapret2, сервер). Поиск идёт по всем парам:
    /// по всем стратегиям и по всем серверам (серверов много, если это подписка).
    /// </summary>
    public static class ServerPairs
    {
        /// <summary>
        /// Стратегия подходит серверу, если рассчитана на тот же транспорт соединения с ним: TLS по TCP (VLESS, Trojan, XHTTP) -
        /// стратегии под MASQUE/HTTP2, QUIC (Hysteria2, XHTTP по h3) - под MASQUE/HTTP3. Стратегии под WireGuard серверу не подходят:
        /// рукопожатие WireGuard у него не встречается. Сама пара стратегией zapret2 не считается.
        /// </summary>
        public static bool Compatible(Strategy strategy, ProxyProfile server) =>
            strategy.UsesZapret && !strategy.IsProxy && strategy.Transport == server.OuterTransport;

        /// <summary>
        /// Пары в порядке поиска: стратегии идут в порядке списка (проверенные первыми), для каждой - все подходящие серверы.
        /// Так быстрый поиск раньше узнаёт, какие серверы вообще отвечают, а неработающий сервер не съедает все проверки подряд.
        /// </summary>
        /// <param name="zapret">Стратегии zapret2: встроенные и свои.</param>
        /// <param name="servers">Серверы как стратегии-заглушки (Profile задан, имя уникально): Subscription.ToStrategies.</param>
        public static List<Strategy> Build(IEnumerable<Strategy> zapret, IEnumerable<Strategy> servers)
        {
            var serverList = servers.ToList();
            var pairs = new List<Strategy>();
            foreach (var strategy in zapret)
                foreach (var server in serverList)
                    if (Compatible(strategy, server.Profile)) pairs.Add(Pair(strategy, server));
            return pairs;
        }

        /// <summary>Идентификатор пары: сохранённые результаты и выбор привязаны и к стратегии, и к серверу.</summary>
        public static string Id(Strategy strategy, Strategy server) => strategy.Id + "@" + server.Id;

        static Strategy Pair(Strategy strategy, Strategy server) => new Strategy
        {
            Id = Id(strategy, server),
            Name = Short(strategy.Name) + " + " + server.Name,
            Transport = strategy.Transport,
            Args = strategy.Args,
            Custom = strategy.Custom,
            Countries = strategy.Countries,
            Profile = server.Profile,
        };

        /// <summary>Имя стратегии без «WARP »: в паре речь о сервере, а не о WARP.</summary>
        public static string Short(string name) =>
            name != null && name.StartsWith("WARP ", StringComparison.Ordinal) ? name.Substring(5) : name;
    }
}
