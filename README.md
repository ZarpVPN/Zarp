# Zarp

[![Build](https://github.com/ZarpVPN/Zarp/actions/workflows/build.yml/badge.svg)](https://github.com/ZarpVPN/Zarp/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/ZarpVPN/Zarp)](https://github.com/ZarpVPN/Zarp/releases/latest)
[![License: MIT](https://img.shields.io/github/license/ZarpVPN/Zarp)](LICENSE)

One-click Cloudflare WARP for networks that block it. Zarp finds a [zapret2](https://github.com/bol-van/zapret2) strategy that gets the WARP handshake through DPI, remembers it and connects. The Windows version can also put zapret2 in front of your own VLESS, Trojan, Hysteria2 or XHTTP server: it finds the strategy that gets the connection to that server through DPI and then tunnels through the server, with routing rules and a choice of programs. Available for Windows, macOS and Android.

![Zarp](docs/screenshot.png)

## Download

| Platform | Download | Requirements |
|---|---|---|
| **Windows** | [**Zarp.exe**](https://github.com/ZarpVPN/Zarp/releases/latest/download/Zarp.exe) · [all releases](https://github.com/ZarpVPN/Zarp/releases) | Windows 10/11 x64, administrator rights. [Cloudflare WARP](https://one.one.one.one/) is installed by Zarp if it is missing |
| **macOS** | [**DMG**](https://github.com/ZarpVPN/Zarp-MacOS/releases/latest) · [all releases](https://github.com/ZarpVPN/Zarp-MacOS/releases) · [source](https://github.com/ZarpVPN/Zarp-MacOS) | Apple Silicon (M1 or newer), macOS 14+, an administrator password once. No WARP app needed |
| **Android** | [**APK**](https://github.com/ZarpVPN/Zarp-Android/releases/latest) · [source](https://github.com/ZarpVPN/Zarp-Android) | Android 8.0+, no root, no WARP app needed |

[![Windows release](https://img.shields.io/github/v/release/ZarpVPN/Zarp?label=Windows)](https://github.com/ZarpVPN/Zarp/releases/latest)
[![macOS release](https://img.shields.io/github/v/release/ZarpVPN/Zarp-MacOS?label=macOS)](https://github.com/ZarpVPN/Zarp-MacOS/releases/latest)
[![Android release](https://img.shields.io/github/v/release/ZarpVPN/Zarp-Android?label=Android)](https://github.com/ZarpVPN/Zarp-Android/releases/latest)


## 💬 Community & Support
Have questions, ideas, or feedback?
Join our [Zarp Community](https://github.com/orgs/ZarpVPN/discussions)!

- ❓ Ask questions and get help
- 💡 Suggest new features
- 📢 Follow announcements
- 🗳️ Vote on upcoming improvements


## Features

- **One button.** The first click searches for the fastest working strategy, later clicks connect right away.
- **Built for WARP.** Strategies target the WARP handshake: MASQUE over QUIC (HTTP/3) and over TLS (HTTP/2).
- **WARP+ subscriptions.** Link your existing WARP+ license in **Settings → Server and endpoints → WARP+**, check the account type and reconnect through Zarp. WARP+ uses the same tunnel and zapret2 strategy; the official WARP client keeps the license, not Zarp.
- **Repeated checks.** Every candidate must pass twice, the second time on a different WARP endpoint when test isolation is on. A quick scan counts only confirmed strategies, and a connection counts only if traffic really goes through WARP.
- **Self-healing.** If the saved strategy stops working, Zarp tries the other verified ones before searching again.
- **Countries.** Filter the strategies by Russia, Iran and China, one or several at once, and tag your own strategies with countries. The filter covers the list, scans, auto-connect, rechecks and saved results.
- **Your own endpoints and server.** Pin WARP to the endpoints you list, or replace WARP with your own VLESS, Trojan or Hysteria2 link, or with a subscription (the `https://` address of a list of such links) (TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP, TLS with ECH, Reality, Vision, Salamander). It is still zapret2 plus an endpoint, not a plain VPN client: Zarp tests every zapret2 strategy against every server and connects with the best pair, and winws2 keeps intercepting the connection to that server while the tunnel is up. The tunnel is the embedded [sing-box](https://github.com/SagerNet/sing-box) and carries TCP and UDP. VLESS over XHTTP, which sing-box cannot speak, is handled by the embedded [Xray-core](https://github.com/XTLS/Xray-core) as a local bridge behind sing-box.
- **Routing and per-program proxy** (your own server). Presets for local networks, Russia, Iran and China, editable Direct, Proxy and Block rules (GeoIP, GeoSite, domains, IP ranges, regular expressions), downloadable V2Ray/Xray `.dat` databases, and a choice of the programs that use the server. See [connection settings](docs/connection-settings.md).
- **Zero setup.** A single `Zarp.exe` with zapret2, sing-box and Xray-core embedded; zapret2 updates itself in the background. If Cloudflare WARP is missing, Zarp downloads the official client from Cloudflare and installs it after you agree.
- **Low overhead.** Only the connection to WARP (or, with your own server, to that one server) is intercepted, and only its handshake packets are changed. The traffic of the tunnel is not touched.
- **Your language.** English, Русский, Español, Português, 中文, हिन्दी, Français, Deutsch and فارسی. Zarp follows the Windows language (English if it is not on the list), and the globe button switches it on the fly. Persian uses right-to-left text; connection links, IP addresses and license keys keep their left-to-right direction.

## Android

[Zarp for Android](https://github.com/ZarpVPN/Zarp-Android) brings the same one-tap flow to phones: the same strategies, double-checked tests, quick and full scan, and eight languages. It works a little differently under the hood:

- **No WARP app needed.** Zarp talks to WARP itself over MASQUE and registers a free WARP device on first use.
- **No root.** It is a regular Android VPN. Fake packets are sent from the tunnel's own UDP socket right before the real handshake.
- **A subset of strategies.** Strategies that need raw sockets (badsum, md5 and similar) are shown as unsupported, WireGuard is not supported yet.

Download the APK from [Releases](https://github.com/ZarpVPN/Zarp-Android/releases/latest). The rest of this page is about the Windows version.

## Requirements

- Windows 10 or 11, x64
- Administrator rights (needed by the WinDivert driver)
- [Cloudflare WARP](https://one.one.one.one/): nothing to do, Zarp installs it for you when it is missing (see below). If you already have it, Zarp finds it wherever it is installed.

## Usage

1. Download [`Zarp.exe`](https://github.com/ZarpVPN/Zarp/releases/latest/download/Zarp.exe) and run it.
2. Press the power button. The first search takes a minute or two.
3. Done. Change the strategy any time in Settings.

**No Cloudflare WARP yet?** On the first press Zarp asks whether to install it. If you agree, it downloads the official installer from Cloudflare (about 60 MB), checks that it is signed by Cloudflare, installs it silently and carries on with the search. The WARP client is proprietary software that Cloudflare licenses to you, so Zarp does not bundle it: it fetches it from Cloudflare exactly as you would in a browser, and by installing it you accept the [Cloudflare WARP terms](https://www.cloudflare.com/application/terms/). If the Cloudflare download site is blocked for you, get `Cloudflare_WARP.msi` any other way (or install WARP yourself with `winget install Cloudflare.Warp`) and put the file into `%LOCALAPPDATA%\Zarp`; Zarp verifies its signature the same way and installs it.

Settings offer two searches. **Quick scan** (also used by the power button) stops after 3 working strategies; the number is adjustable. **Full scan** tests every strategy: slower, but nothing is skipped, so it finds the fastest one for sure. With your own server a strategy is a pair of a zapret2 strategy and a server: the scans go through all pairs (each strategy against every server of a subscription that it suits), and the number of pairs can be large, so a full scan can take a long time.

**Server and endpoints**, **Routing** and **Per-app proxy** in Settings are described in [connection settings](docs/connection-settings.md). The short version: the official WARP client has no per-app mode and cannot route by country or domain, so routing and per-app proxy work with **your own server** (paste one link or a subscription in **Server and endpoints** and switch it on), while custom endpoints belong to WARP. The country filter works in both modes: with your own server it chooses the zapret2 strategies that are tried against the server. The country filter and the routing presets are independent.

**Have WARP+?** Open **Settings → Server and endpoints**, turn off **Use my own server instead of WARP** and open **WARP+**. Copy your license key from **Settings → Account** in the 1.1.1.1 app on your phone, paste it and press **Apply key**. The window confirms the account type reported by WARP; a successful command alone does not prove that WARP+ is active. Reconnect with Zarp after linking the license. If WARP is not installed yet, connect once to let Zarp install it first. See [WARP+ details and troubleshooting](docs/connection-settings.md#warp-subscription).

Closing the window asks whether to hide Zarp in the tray or quit. Select **Remember my choice** to make that action the default. Settings → **On close** lets you choose **Ask every time**, **Hide to tray** or **Exit the app**. **Exit** in the tray menu always quits.

> [!NOTE]
> **"Windows protected your PC"?** Older releases and local builds may be unsigned. Release signing requires maintainer setup; see [code signing](docs/code-signing.md). A trusted signature identifies the publisher, but new releases can still trigger SmartScreen while reputation builds. [Verify the download](#verify-the-download) before running it.

> [!NOTE]
> Turn off any other VPN (Happ, v2rayN, Clash, AmneziaVPN, ...) before searching. The traffic of WARP (or of your own server) would go through its tunnel, so every test would measure that VPN instead of your network and no strategy would be found. Zarp warns you, asks before searching anyway, and never overwrites saved results with failures from such a run. Connecting with a strategy you already saved works either way.

Virtual LAN adapters such as Radmin VPN are checked against the Windows routes to WARP endpoints. An active adapter that only carries its own LAN traffic does not trigger the VPN warning. If the routing table cannot be read, Zarp keeps the warning as a precaution.

**WARP registration or IPC timeout?** Zarp waits and reads the existing registration again before creating a new one. A timeout is not treated as proof that the device is unregistered. A delayed registration, including an "Old registration is still around" response, is checked again without deleting the account or its WARP+ license. If the service remains unresponsive, restart the **CloudflareWARP** Windows service or restart Windows, then try again. Restarting that service interrupts the WARP connection; reconnect through Zarp afterwards.

> [!WARNING]
> Windows Defender may flag WinDivert as a hacktool. This is a known false positive. Zarp offers to add its zapret2 folder to Defender exclusions when that happens. The same offer is made for the sing-box folder if you use your own server and the antivirus blocks `sing-box.exe`, and for the Xray folder if the link uses XHTTP and the antivirus blocks `xray.exe`.

Command line: `--connect` connects on start, `--autostart` starts minimized to tray (used by the autostart task).

### Verify the download

Every release is built by [GitHub Actions](.github/workflows/build.yml) straight from this repository. The release notes list the SHA-256 of `Zarp.exe`, and GitHub signs a build attestation for it:

```powershell
Get-FileHash .\Zarp.exe                                # compare with the release notes
gh attestation verify .\Zarp.exe --repo ZarpVPN/Zarp     # proves the file was built here
```

### What Zarp changes on your system

- If Cloudflare WARP is not installed and you agree, installs it from the official Cloudflare installer (Windows Installer, `msiexec /i ... /qn`). Nothing is installed without your consent. The installer is deleted afterwards.
- Runs as administrator. While a strategy is active, `winws2` from zapret2 loads the WinDivert driver and modifies only the handshake packets of the WARP connection (with your own server: of the connection to that server, which is its address and port, nothing else).
- Changes the tunnel protocol and MASQUE options of your WARP client through `warp-cli` to match the chosen strategy. During a search it also pins a WARP endpoint for each test and resets it to automatic afterwards (when you list your own endpoints, the connection stays pinned to the one that passed the check).
- Only if you use your own server: extracts sing-box (about 45 MB) to `%LOCALAPPDATA%\Zarp\singbox` and, while connected, creates a network adapter named `Zarp` that carries the system's traffic, with routes and firewall rules that keep DNS from bypassing it. They disappear when you disconnect, or when you exit with **Disconnect on exit** on (the default). The first time, Windows also installs the Wintun network driver that sing-box carries inside itself; the driver stays installed afterwards. If the antivirus blocks `sing-box.exe`, Zarp offers a Defender exclusion for that folder, as it does for zapret2.
- Only if the link of your own server uses XHTTP: also extracts Xray-core (about 36 MB) to `%LOCALAPPDATA%\Zarp\xray` and runs `xray.exe` as a local SOCKS5 bridge on `127.0.0.1` (a random port with a random password) that sing-box sends the traffic to. To keep the connection of Xray to your server from looping back into the `Zarp` adapter, sing-box sends everything from `xray.exe` straight out and the address of your server is left out of the adapter's routes. Xray adds no adapter, driver or firewall rule of its own and stops together with sing-box.
- Extracts zapret2 and keeps its settings and log in `%LOCALAPPDATA%\Zarp`.
- Only if you turn them on: a Task Scheduler task named `Zarp` for **Start with Windows**, and a Windows Defender exclusion for the zapret2 folder, or for the sing-box folder (and the Xray folder for XHTTP links) if you use your own server (Zarp asks first).

### Uninstall

1. In Settings, turn off **Start with Windows** (or run `schtasks /Delete /TN Zarp /F`).
2. Choose **Exit** in the tray menu, then delete `Zarp.exe` and the `%LOCALAPPDATA%\Zarp` folder.
3. Restore the WARP defaults: `warp-cli tunnel protocol reset`, `warp-cli tunnel masque-options reset`, `warp-cli tunnel endpoint reset`.
4. If you added the Defender exclusion, remove it in an administrator PowerShell: `Remove-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Zarp\zapret2"` (and the same for `...\Zarp\singbox` and `...\Zarp\xray` if you used your own server).
5. If you used your own server and want the Wintun network driver gone too, find its package with `pnputil /enum-drivers` (original name `wintun.inf`) and remove it with `pnputil /delete-driver <oemNN.inf> /uninstall`. Other VPN programs may use the same driver.
6. If Zarp installed Cloudflare WARP for you and you no longer need it, remove it like any program: Settings → Apps → **Cloudflare One Client** (called **Cloudflare WARP** in older versions), or `winget uninstall Cloudflare.Warp`.

### Privacy

Zarp does not collect, store or send any personal data, and it has no telemetry. It makes only these network requests:

- `https://www.cloudflare.com/cdn-cgi/trace`, while testing or connecting, and every 15 seconds while WARP is connected, to check that traffic goes through WARP and to measure latency. With your own server the same page is requested through the server.
- Only if you use your own server: the connection to that server. Its link, with the password, is kept in `zarp.json` in your data folder and never written to the log.
- Only if you use a subscription: one `https://` request to the address you set, when you save it, press Save again to refresh it, or connect with a list that is older than 12 hours. The token in that address is kept in `zarp.json` and never written to the log; the list of servers it returns is kept in `subscription.json`.
- Only if you apply a WARP+ key: Zarp passes it to the official local `warp-cli`, which contacts Cloudflare to link the device. Zarp does not store the key in its settings or log, and displays only a known account type from the registration response. Cloudflare's client manages and retains the license independently of Zarp.
- Only if you press Download in **GeoIP and GeoSite**: the address you set there. By default these are `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat` and `.../geosite.dat`.
- `https://downloads.cloudflareclient.com/`, only if Cloudflare WARP is missing and you agreed to install it, to download the official installer.
- `https://github.com/bol-van/zapret2/releases` (the GitHub API as a fallback), to check for and download zapret2 updates. Turn off **Update zapret2 automatically** in Settings to disable this.

WARP itself is a Cloudflare service covered by the [Cloudflare WARP privacy policy](https://www.cloudflare.com/application/privacypolicy/). Requests to GitHub are covered by the [GitHub privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

## How it works

A strategy is a WARP tunnel protocol plus a winws2 profile. During the search Zarp starts winws2 for each strategy, connects WARP via `warp-cli`, waits for `Connected` and checks `cdn-cgi/trace` for `warp=on`. Score is `connect time + 4 × ping`. The fakes are real packets from services that are not blocked (QUIC/TLS for google, vk and gosuslugi), because DPI ignores empty fakes.

With your own server a strategy is a pair of a zapret2 strategy and a server. TLS over TCP (VLESS, Trojan, XHTTP) is tried with the TLS strategies, QUIC (Hysteria2) with the QUIC ones. For each pair Zarp starts winws2 so that it intercepts only the connection to the address and port of that server, then checks the server twice with a real HTTPS request through sing-box. The best pair wins; sing-box then starts with a network adapter that carries the system's traffic, applying your routing rules and program selection, and winws2 keeps running next to it. Details are in [connection settings](docs/connection-settings.md).

The built-in strategies and where their syntax comes from are described in [docs/strategies.md](docs/strategies.md).

App data lives in `%LOCALAPPDATA%\Zarp`: settings, log, extracted zapret2, sing-box (`singbox`) and Xray (`xray`), the saved list of servers of your subscription (`subscription.json`, it holds the server links), downloaded GeoIP and GeoSite databases (`geodata`) and `strategies.txt` for your own strategies:

```
# name | transport (h3, h2, wg) | winws2 profile args | countries (optional)
My QUIC | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=8
My TLS  | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,sld | ru,ir,cn
```

See the [zapret2 manual](https://github.com/bol-van/zapret2/blob/master/docs/manual.en.md) for `--lua-desync` syntax.

## Building

```powershell
.\build.ps1 -Version 1.0.0   # dist\Zarp.exe
```

Requires the .NET SDK 6 or later (the target is .NET Framework 4.8). `tools/fetch-zapret.ps1` packs the latest zapret2 release into `vendor/zapret2.zip`, `tools/fetch-singbox.ps1` packs the pinned sing-box release (its SHA-256 is checked) into `vendor/singbox.zip`, and `tools/fetch-xray.ps1` does the same for the pinned Xray-core release (`vendor/xray.zip`); all three get embedded into the exe, which makes it about 32 MB. Without `vendor/singbox.zip` the build works but your own server mode reports that sing-box is missing; without `vendor/xray.zip` only the XHTTP links report that Xray is missing.

GitHub Actions builds every push. A `v*` tag publishes `Zarp.exe`; releases are unsigned until [SignPath is configured](docs/code-signing.md) and the repository variable `SIGNPATH_ENABLED` is set to `true`. Once signing is enabled, a missing configuration or invalid signature stops the release. Release notes report the signing status.

UI regression checks (Windows; no WARP/WinDivert changes). They open every window in every language and fail on clipped or overlapping text, they run every built-in strategy through the real `winws2 --dry-run`, which parses the parameters without intercepting anything, and they start real VLESS, Trojan and Hysteria2 servers on localhost (no network adapter) to check the server mode and the routing rules:

```powershell
dotnet build tests/Zarp.Tests/Zarp.Tests.csproj -c Release -o build/tests
.\build\tests\Zarp.Tests.exe --results build/test-results
```

Tests run independently and continue after failures. GitHub Actions shows the failed cases in the run summary and uploads the `zarp-test-results` artifact even when tests fail. It includes JUnit XML, stdout/stderr, exit codes and the exact winws2 configurations. See [test reporting and targeted runs](docs/testing.md).

### Translations

All UI strings live in [`src/Zarp/Lang`](src/Zarp/Lang), one `key = value` file per language, with `en.txt` as the reference. To fix a translation, edit the file. To add a language, copy `en.txt` to `<code>.txt`, translate the values and add the code to `L.Languages` in [`L.cs`](src/Zarp/Core/L.cs). The tests check that every language has the same keys and placeholders as English.

## Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

- Committers and reviewers: [ZarpVPN](https://github.com/ZarpVPN)
- Approvers: [ZarpVPN](https://github.com/ZarpVPN)
- Privacy policy: see [Privacy](#privacy)

Only `Zarp.exe` built by GitHub Actions from this repository is signed, and every signing request is approved manually. The bundled zapret2 and WinDivert files are unmodified upstream binaries, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Signing starts with the first release after the SignPath Foundation application is approved; earlier releases are unsigned.

## License

Zarp for Windows is released under the [MIT License](LICENSE). [Zarp for Android](https://github.com/ZarpVPN/Zarp-Android) is a separate project under GPL-3.0.

`Zarp.exe` bundles [zapret2](https://github.com/bol-van/zapret2) (MIT) with LuaJIT (MIT) and zlib, [WinDivert](https://reqrypt.org/windivert.html) (LGPL-3.0), the Cygwin DLL (LGPL-3.0-or-later) and [sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0-or-later, started as a separate program, with the [Wintun](https://www.wintun.net/) driver inside it under the Wintun Prebuilt Binaries License), [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0 with GPL-3.0-or-later modules inside, unmodified, started as a separate program), plus country IP ranges from [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (CC0). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for versions, license texts and source links.

Cloudflare and WARP are trademarks of Cloudflare, Inc. Zarp is an independent project, not affiliated with or endorsed by Cloudflare. Zarp does not bundle or redistribute any Cloudflare software: it only drives the WARP client through `warp-cli`, and when the client is missing it fetches the official installer from Cloudflare on your request.
