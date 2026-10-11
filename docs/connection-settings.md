# Connection settings

Open **Settings** to change them. Settings are saved locally and apply on the next connection. Changing the server or the WARP endpoints clears the previous test results, because they described another connection.

| Setting | WARP (official client) | Your own server |
|---|---|---|
| zapret2 strategies | yes | yes, always: a strategy is a pair of a zapret2 strategy and a server |
| Country filter for strategies, your own strategies | yes | yes, through the strategies of the pairs |
| Custom WARP endpoints | yes | not used |
| Routing presets, GeoIP and GeoSite | no | yes |
| Per-app proxy | no | yes |

The official WARP client has no per-app mode and cannot route by country or domain, and Zarp does not replace it. These two features need a tunnel that Zarp controls, so they work with **your own server**, which Zarp connects through sing-box and its own network adapter. The windows say so when WARP is the active mode.

## Server and endpoints

Open **Settings → Server and endpoints**.

**Custom WARP endpoints.** Enter one numeric `IP:port` or `[IPv6]:port` per line. Blank lines and `#` comments are accepted. An empty list restores the default WARP addresses. The addresses must be compatible WARP endpoints, not arbitrary proxies: the field cannot turn another server into WARP. A scan rotates through your list, rechecks included, and the connection uses the address on which the strategy passed its last check. With a single address a recheck uses a fresh connection but cannot isolate the endpoint, and the result says so (works, 2 checks, not independent). While a strategy is active, winws2 also intercepts your addresses, even outside the Cloudflare ranges.

**Use my server instead of WARP.** Paste one link, or the address of a subscription (see below):

| Protocol | Supported parameters |
|---|---|
| VLESS | UUID, TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP (see below), TLS (also with ECH), Reality (`pbk`, `sid`), Vision (`flow=xtls-rprx-vision`), uTLS fingerprint |
| Trojan | password, TLS (also with ECH), TCP, WebSocket, gRPC, HTTPUpgrade |
| Hysteria2 / hy2 | password, TLS (also with ECH), SNI, ALPN, Salamander obfuscation |

Common parameters are `sni`, `peer`, `alpn`, `insecure` and `allowInsecure`. Transport fields are `type`, `path`, `host` and `serviceName`. Unsupported transports and parameters are rejected, not silently dropped. No port hopping and no arbitrary JSON. The window says why a link is refused: another kind of link, or an unsupported transport, parameter or security mode, is named, but the password and the values never are. Certificate verification stays on unless the link turns it off.

**ECH** (Encrypted Client Hello). A link with TLS may carry `ech=` with the ECH configuration of the server (base64, as panels write it; the URL-safe form is accepted too). The server name is then sent encrypted, and the connection is refused when the server does not accept that configuration: a wrong list does not silently fall back to plain TLS. ECH works for VLESS and Trojan over TLS, for Hysteria2 over QUIC and for XHTTP. With ECH the uTLS fingerprint (`fp`) of a sing-box connection is not applied, because sing-box uses its standard TLS for ECH. The parameter is refused for links without TLS (Reality, none).

**VLESS over XHTTP** (`type=xhttp`, the links that panels such as 3x-ui and clients such as v2rayN produce) takes these parameters. `path` (default `/`) and `host` set the request path and the Host header; with no TLS and no `host` the Host header is the server name from the link. `mode` is `auto` (default), `packet-up`, `stream-up` or `stream-one`. `extra` is the JSON object of XHTTP settings that Xray-based clients put into the link (padding, `xmux`, headers, `downloadSettings` and so on); it is passed to Xray as it is, and Xray itself checks its contents when the connection starts. `security` is `none`, `tls` or `reality`; for `tls` the usual `sni`, `alpn` and `fp` apply, and `pcs` (SHA-256 hash of the server certificate, hex, colons allowed, several separated by commas) and `vcn` (names the certificate must be valid for) are accepted; for `reality` the usual `pbk`, `sid`, `sni` and `fp`, plus `spx` (spider path) and `pqv` (ML-DSA-65 public key). `encryption` must be `none`, and `flow` must stay empty. Panels such as 3x-ui also write the padding twice, as `x_padding_bytes` (a number or a range such as `100-1000`) next to `extra`: `extra` wins when it is there, and without it `x_padding_bytes` sets the padding. For Reality links they add `support-x25519mlkem768=true`, a hint for other clients (Mihomo) to offer the hybrid key exchange; Xray chooses the key exchange by the fingerprint, so the parameter is accepted and changes nothing. The old name `splithttp`, `fm` and any other parameter are rejected by name.

Xray removed `allowInsecure`, so an XHTTP link with `insecure=1` or `allowInsecure=1` is refused with an explanation. A self-signed certificate is trusted by its hash instead: add `pcs` to the link. The password and the UUID never appear in the strategy name, the log or an error message, and the saved link stays in `zarp.json` in your data folder.

**Subscriptions.** Instead of one link you can paste the `https://` address of a subscription, a list of server links that a panel (3x-ui and similar) gives out. **Save** downloads the list at once, so the window can say how many servers it holds, and **Save** pressed again loads it anew. The address must start with `https://`, with no name, password or `#` in it, because the access token is part of the address: plain `http://` is refused with that explanation. The list is read as base64 or as plain text, one link per line; links of other kinds (`vmess://`, `ss://`, `tuic://` and so on) and links Zarp cannot read are skipped and counted in the log, not hidden. An answer in JSON or a web page is named as such. If the panel does not answer with a list of links, Zarp asks once more as a common client (`v2rayN`), because panels pick the format by the name of the client. At most 200 servers are taken, the answer must be under 2 MB and arrive within 25 seconds, redirects must stay on `https://`, and the certificate of the panel is always checked. The address and its token never appear in the log or in error messages.

The servers are saved in `subscription.json` in your data folder (it holds the links, so it is as private as `zarp.json`) and the program works from that list without the network and after a restart. When you connect and the list is older than 12 hours, Zarp refreshes it; if the panel cannot be reached it goes on with the old list and says so in the log. Every pair of a strategy and a server is a line in the strategy list of **Settings**, named after the strategy and the server (as the panel names it). With no pair chosen, **Connect** searches the pairs as described below and connects with the best; the chosen pair is remembered. If the chosen pair stops passing, the other verified pairs are tried by score before searching again. A subscription with an XHTTP server prepares Xray for the tests; one without does not.

**Strategies with your own server.** Your own server is zapret2 plus an endpoint, not a plain VPN client, and zapret2 is not optional here. A strategy is a pair: a zapret2 strategy and a server. TLS over TCP (VLESS including Reality, Trojan, XHTTP) is paired with the TLS strategies of the catalog (the ones for MASQUE over HTTP/2), QUIC (Hysteria2, XHTTP whose ALPN is only `h3`) with the QUIC strategies. WireGuard strategies are not used. For each pair Zarp starts `winws2` so that it intercepts only the connection to the address and port of that server, in both directions, and changes the handshake packets that the strategy names (a server in your local network or on this computer is intercepted too). Then it checks the server with a real HTTPS request through sing-box, twice, as for WARP. The search goes through all pairs: a strategy against every server of a subscription that it suits, then the next strategy. A quick scan stops after the number of working pairs set in Settings; a full scan tests all of them. A subscription of many servers means many pairs, and a pair that does not pass waits for the test timeout, so a full scan can take long (**Cancel** works at any time). The best pair (connection time plus four times the ping) is connected and remembered. winws2 keeps running next to the tunnel, because every new connection to the server has to pass DPI the same way; if it stops, Zarp says so. The country filter and your own strategies from `strategies.txt` (transports `h2` and `h3`) apply to the pairs through their strategies. Options that only concern WARP (intercepting WARP addresses only, another endpoint for rechecks) do nothing here. Without zapret2 the connection is refused: there is no strategy that skips it.

The server replaces WARP: Zarp does not register a WARP device and does not need the WARP client. The check requires a valid HTTPS answer from `cdn-cgi/trace` that came through the server, and the connection time is the time of the first answer. If the server has no IPv6 access, turn off **IPv6 through the server** in the same window. DNS requests go to the DNS server from that window (1.1.1.1 by default) through your server.

The engine is [sing-box 1.13.14](https://github.com/SagerNet/sing-box/tree/v1.13.14), GPL-3.0-or-later, embedded into `Zarp.exe` and started as a separate process. sing-box cannot speak XHTTP, so for XHTTP links it hands the traffic to [Xray-core 26.7.28](https://github.com/XTLS/Xray-core/tree/v26.7.28) (MPL-2.0, with GPL-3.0-or-later modules inside), which is embedded and started the same way, and only for such links. See [third-party notices](../THIRD_PARTY_NOTICES.md).

## Routing

Open **Settings → Routing**, switch the rules on and choose one preset. The built-in presets (local networks, Russia, Iran, China) send local addresses and the addresses of the country directly, and everything else goes through the server. **Edit** opens the three groups **Direct**, **Proxy** and **Block**, one rule per line. You can edit the built-in presets and reset them, and create and delete your own. Priority is **Block, then Proxy, then Direct**. Traffic that no rule matches goes through the server, with one exception made for a desktop: local network addresses stay direct unless a rule says otherwise, so the router, printers and file shares keep working.

| Rule | Matches |
|---|---|
| `geoip:ru`, `geoip:private` | GeoIP category (`private` is built in) |
| `geosite:youtube` | GeoSite category |
| `geosite:google@cn`, `geosite:google@!cn` | entries with the attribute, or without it |
| `domain:example.com` or `example.com` | the domain and its subdomains |
| `full:example.com` | exactly this domain |
| `keyword:example` | domains that contain the text |
| `regexp:pattern` | RE2 expression for the domain |
| `1.2.3.4`, `2001:db8::/32` | IPv4 or IPv6 address or range |

Blank lines and lines that start with `#` are ignored. Use punycode for international domain names. Syntax is checked when you save, with the real line number. Unknown categories, missing databases and expressions that sing-box rejects stop the connection with an explanation: a rule is never skipped silently.

**GeoIP and GeoSite** opens the download settings. Each database has an editable HTTPS address and a Download or Update button. The defaults are the V2Ray/Xray `.dat` files of [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat). Formats `.db`, `.srs` and MMDB are not accepted. Downloads are explicit, up to 64 MiB per file, with a three minute limit and HTTPS-only redirects. Every record is validated before the file replaces the old one, so a failed or cancelled update keeps the last good database. A different address has a separate stored copy. Local ranges need no download. For the default source Zarp also carries the ranges of Russia, Iran and China from [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (CC0), used until you download your own GeoIP. GeoSite always needs a download.

## Per-app proxy

Open **Settings → Per-app proxy**, switch **Proxy selected programs only** on and choose programs. The list shows running programs, Start menu shortcuts and registered application paths. Search matches the name and the path, and **Add program** takes any `.exe`. Only the chosen programs use the server (and the routing rules), everything else connects as usual. A program is recognized by the path of its `.exe`, ignoring case. Browsers and launchers often start helper programs of their own, so choose the one that really makes the connection. Zarp itself always goes through the server while the mode is on, because that is how it checks the adapter.

If the mode is on and none of the chosen programs exists any more, the connection is refused instead of falling back to all programs.

## Strategy countries

The filter above the strategy list takes several countries at once: the visible list, quick and full scans, the power button, rechecks and the use of saved results all see the union of the chosen countries. **All** clears the filter. While a country is chosen, strategies without desync (plain WARP) and strategies without a country tag are left out. Changing the filter does not delete saved results. Country tags are suggestions for what to test, not proof that a strategy works with every provider in that country. Generic Google QUIC fakes and TLS splits are offered for all three countries, strategies built around VK or Gosuslugi fakes only for Russia. The strategy catalog is in [strategies.md](strategies.md).

A custom strategy may have an optional fourth column:

```text
My TLS | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,sld | ru,ir,cn
```

Lines with three columns stay valid and appear under **All**. Adding or removing the country column keeps the strategy identity, so its saved results stay.

The country filter and the routing presets are independent.

## How your own server is connected

Zarp starts winws2 with the strategy of the pair and checks the server with a local sing-box that has no adapter: a real HTTPS request goes through it twice, so an unreachable server never takes your traffic. Then sing-box starts again with a network adapter named **Zarp** that routes the whole system through it, and winws2 keeps running next to it (`auto_route`, `strict_route`, gVisor stack). The adapter uses the Wintun driver, which is carried inside sing-box and installed the first time an adapter is created (that needs administrator rights, which Zarp always has). The driver stays installed after the adapter is gone, as it does for other programs that use it. The server name is resolved first by the system DNS, while the network is still untouched. After the adapter is up, Zarp sends a request of its own through it and removes the adapter at once if nothing passes. DNS requests from every program are answered by sing-box and sent through the server, with reverse mapping so that domain rules also work for connections that only show an IP. Streams that carry a domain (TLS, HTTP, QUIC) are sniffed for domain rules.

The configuration, which holds the password, is written for sing-box to read and deleted right after it starts. The local test port listens on 127.0.0.1 only, speaks SOCKS5 and accepts only a random login and password; the check does not use an HTTP proxy, whose password challenge sing-box ends with a connection reset that Windows can turn into a lost answer. `sing-box.exe` is started only if it is byte for byte the file embedded in `Zarp.exe`, and the file is locked against replacement while it starts. Disconnecting, exiting (with **Disconnect on exit**) and a Windows shutdown stop sing-box, and Windows then removes the adapter and its routes. A sing-box left behind by a crash is picked up on the next start, or stopped if it cannot be recognized.

**XHTTP links** add one more program in the chain: apps → `Zarp` adapter → sing-box → Xray → your server. Zarp starts `xray.exe` before sing-box, as a SOCKS5 bridge that listens on 127.0.0.1 only, on a random port, and accepts only a random login and password (a new one for every start). sing-box connects to it as to a SOCKS5 proxy and the bridge carries TCP and UDP to the server by VLESS over XHTTP. Xray reaches your server by the address that Zarp resolved at the start of the operation. So that its own connection does not come back into the adapter, sing-box is told to send everything from `xray.exe` straight out, before any routing rule or program selection, and the address of the server is left out of the adapter's routes. The UUID and the keys exist only in the configuration of Xray, which, like the sing-box one, is deleted right after the start; sing-box never sees them. `xray.exe` is started only if it is byte for byte the embedded file, and it is extracted to `%LOCALAPPDATA%\Zarp\xray` only when the link needs it. While the server is checked without the adapter, Xray writes the reason of a failure to its log (that level also records page addresses), and Zarp shows the last failure in its own log without addresses; with the adapter Xray logs warnings only, and its access log is always off. Xray's log is deleted when it stops. If Xray stops while sing-box is still running, Zarp reports it and stops sing-box too, because the adapter would otherwise take all traffic and send it nowhere.

## Limitations

- IP lists describe address allocations, not guaranteed physical locations.
- Programs with their own encrypted DNS or Encrypted Client Hello can hide a domain from domain rules. IP rules still apply.
- Another VPN with its own adapter conflicts with this one. Zarp warns about it, as it does for WARP.
- Your own server mode, routing and per-app proxy are not available in the WARP mode (see the table above).
- Whether a strategy gets the connection to your server through the DPI of your provider can only be found by trying: the tests prove that the right arguments and the right WinDivert filter reach winws2, not the effect on a real DPI. A server whose address is blocked outright cannot be helped by any strategy, and strategies change nothing for a protocol they cannot see (Hysteria2 with Salamander, for example, does not look like QUIC).
- Subscriptions in JSON form (Xray or sing-box configurations), arbitrary JSON and Hysteria2 port hopping are not supported; subscriptions must give links.
- XHTTP: VLESS only; no `allowInsecure` (use `pcs`), no VLESS encryption or `fm` parameters. A second hop through a local bridge costs a little latency, and UDP travels inside the XHTTP stream like TCP does.
- No strategy can promise a permanent DPI bypass, and candidates need testing on each provider.

## Verification

The regression tests [parse every kind of link](testing.md), start real VLESS (TCP, WebSocket, HTTPUpgrade), Trojan (TCP, gRPC) and Hysteria2 (with Salamander) servers on localhost and pass TCP and UDP traffic through each of them. They start real Xray servers with XHTTP (plain, TLS with a pinned certificate, with ECH, Reality; every mode, with and without `extra`) and pass TCP and UDP traffic through the whole chain of the probe port, sing-box and the Xray bridge, start real VLESS, Trojan and Hysteria2 servers with ECH keys (a wrong ECH list must break the connection), read subscriptions from a real HTTPS server on localhost (TLS, redirects, compression, limits, cancelling), and ask Xray and sing-box themselves to accept every generated configuration. They run the connection check of Zarp through a real sing-box probe port (SOCKS5 with its login and password), feed it every kind of answer from a fake server and check that a changed `sing-box.exe` or `xray.exe` is refused. For every built-in strategy and every kind of server (TLS or QUIC, IPv4 or IPv6, local network, this computer) they let the real `winws2` verify the arguments (`--dry-run`) and write the WinDivert filter it builds (`--wf-save`), and check that the filter holds the address and the port of the server and nothing of the WARP ranges. The search over pairs, the order of the search and the fallbacks run in the engine tests with a stand-in for `winws2` that only lives, and with a model of DPI that lets one combination of a strategy and a server through. They check the routing rules with the real sing-box (priority, every kind of rule, GeoIP and GeoSite databases, per-app selection by process path), validate `.dat` files, the download rules and every window in every language. They never start the network adapter, WARP or WinDivert.

What the tests cannot cover is the adapter itself on your network: routes, DNS and the firewall are Windows and sing-box territory, and so is the way the connection of `xray.exe` to the server stays out of the adapter. That is why the adapter check and the cleanup described above exist.
