using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Zarp.Core
{
    internal static class WarpRegistrationApi
    {
        internal static readonly string[] Hosts =
        {
            "api.cloudflareclient.com", "api.devices.cloudflare.com",
            "zero-trust-client.cloudflareclient.com", "notifications.cloudflareclient.com",
        };

        // Cloudflare pins these orchestration addresses independently of DNS:
        // https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/#client-orchestration-api
        internal static readonly string[] PinnedAddresses =
        {
            "162.159.137.105", "162.159.138.105", "2606:4700:7::a29f:8969", "2606:4700:7::a29f:8a69",
        };

        internal static async Task<IReadOnlyList<string>> ResolveAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var lookups = Hosts.Select(ResolveHostAsync).ToArray();
            // DNS is not cancellable on .NET Framework. Bound the wait; late results do not change the active filter.
            await Task.WhenAny(Task.WhenAll(lookups), Task.Delay(5000, ct));
            ct.ThrowIfCancellationRequested();
            return PinnedAddresses.Concat(lookups.Where(t => t.Status == TaskStatus.RanToCompletion)
                .SelectMany(t => t.Result).Where(IsPublicAddress).Select(ip => ip.ToString())).Distinct().Take(64).ToArray();
        }

        static async Task<IPAddress[]> ResolveHostAsync(string host)
        {
            try { return await Dns.GetHostAddressesAsync(host); }
            catch (Exception) { return new IPAddress[0]; }
        }

        internal static bool IsPublicAddress(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IPAddress.IsLoopback(ip)) return false;
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return b[0] != 0 && b[0] != 10 && b[0] < 224 && !(b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                    && !(b[0] == 192 && b[1] == 168) && !(b[0] == 169 && b[1] == 254);
            return ip.AddressFamily == AddressFamily.InterNetworkV6 && !ip.Equals(IPAddress.IPv6Any)
                && !ip.IsIPv6LinkLocal && !ip.IsIPv6SiteLocal && !ip.IsIPv6Multicast && (b[0] & 0xFE) != 0xFC;
        }
    }
}
