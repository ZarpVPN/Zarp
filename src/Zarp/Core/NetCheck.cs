using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Zarp.Core
{
    /// <summary>Поиск сторонних VPN/TUN-адаптеров, через которые может уходить трафик WARP.</summary>
    public static class NetCheck
    {
        static readonly Regex VpnLike = new Regex(
            @"\b(?:tun|tap)\d*\b|wintun|wireguard|sing-box|clash|mihomo|v2ray|xray|hiddify|nekoray|amnezia|outline|openvpn|vpn|happ|zerotier|tailscale",
            RegexOptions.IgnoreCase);
        // Системные механизмы IPv6 имеют тип Tunnel, но не являются сторонними VPN.
        static readonly Regex WindowsIpv6Tunnel = new Regex(
            @"\b(?:teredo|isatap|6to4|6-to-4|6over4)\b",
            RegexOptions.IgnoreCase);

        static readonly IPAddress[] RouteTargets =
        {
            IPAddress.Parse("162.159.198.1"), IPAddress.Parse("162.159.198.2"), IPAddress.Parse("162.159.192.1"),
            IPAddress.Parse("2606:4700:102::1"), IPAddress.Parse("2606:4700:d0::1"),
        };

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern uint GetBestInterfaceEx([In] byte[] destination, out uint interfaceIndex);

        // Только чтение таблицы маршрутов Windows: пакеты не отправляются и настройки адаптеров не меняются.
        internal static int? BestInterface(IPAddress destination)
        {
            try
            {
                bool v6 = destination.AddressFamily == AddressFamily.InterNetworkV6;
                var address = new byte[v6 ? 28 : 16];
                BitConverter.GetBytes((ushort)(v6 ? 23 : 2)).CopyTo(address, 0); // Windows AF_INET6 / AF_INET
                destination.GetAddressBytes().CopyTo(address, v6 ? 8 : 4);
                if (v6) BitConverter.GetBytes((uint)destination.ScopeId).CopyTo(address, 24);
                return GetBestInterfaceEx(address, out var index) == 0 && index > 0 ? (int?)index : null;
            }
            catch (DllNotFoundException) { return null; }
            catch (EntryPointNotFoundException) { return null; }
        }

        internal static bool CarriesWarpTraffic(int ipv4Index, int ipv6Index, Func<IPAddress, int?> lookup)
        {
            bool known = false;
            foreach (var destination in RouteTargets)
            {
                int? route = lookup(destination);
                if (!route.HasValue || route.Value <= 0) continue;
                known = true;
                int candidate = destination.AddressFamily == AddressFamily.InterNetworkV6 ? ipv6Index : ipv4Index;
                if (candidate > 0 && route.Value == candidate) return true;
            }
            return !known; // если таблицу прочитать не удалось, предупреждение остаётся консервативным
        }

        internal static bool IsForeignVpnAdapter(string name, string description, NetworkInterfaceType type,
            OperationalStatus status, IEnumerable<IPAddress> gateways)
        {
            if (status != OperationalStatus.Up) return false;
            string text = name + " " + description;
            // свой адаптер Zarp (подключение через собственный сервер) тоже не сторонний
            if (text.IndexOf("Cloudflare", StringComparison.OrdinalIgnoreCase) >= 0 || WindowsIpv6Tunnel.IsMatch(text)
                || string.Equals(name, SingBox.TunName, StringComparison.OrdinalIgnoreCase))
                return false;
            bool tunnelType = type == NetworkInterfaceType.Tunnel || type == NetworkInterfaceType.Ppp;
            if (!tunnelType && !VpnLike.IsMatch(text)) return false;
            return gateways != null && gateways.Any(g => g != null && !g.Equals(IPAddress.Any) && !g.Equals(IPAddress.IPv6Any));
        }

        /// <summary>Активные VPN-адаптеры со шлюзом; системные IPv6-туннели не учитываются.</summary>
        public static List<string> ForeignVpnAdapters()
        {
            var res = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    try
                    {
                        if (ni.OperationalStatus != OperationalStatus.Up) continue;
                        var properties = ni.GetIPProperties();
                        if (!IsForeignVpnAdapter(ni.Name, ni.Description, ni.NetworkInterfaceType, ni.OperationalStatus,
                            properties.GatewayAddresses.Select(g => g.Address))) continue;
                        int v4 = -1, v6 = -1;
                        if (ni.Supports(NetworkInterfaceComponent.IPv4)) v4 = properties.GetIPv4Properties().Index;
                        if (ni.Supports(NetworkInterfaceComponent.IPv6)) v6 = properties.GetIPv6Properties().Index;
                        // Radmin и другие LAN-оверлеи могут быть активны, не забирая интернет-трафик WARP.
                        if (CarriesWarpTraffic(v4, v6, BestInterface)) res.Add($"{ni.Name} ({ni.Description})");
                    }
                    catch (NetworkInformationException) { } // исчезнувший адаптер не отменяет проверку остальных
                }
            }
            catch { }
            return res;
        }
    }
}
