# Regression tests

Run on Windows with the .NET SDK and .NET Framework 4.8:

```powershell
dotnet build tests/Zarp.Tests/Zarp.Tests.csproj -c Release -o build/tests
.\build\tests\Zarp.Tests.exe --results build/test-results
```

Each independent case runs in its own STA process with fresh test data. Cases run sequentially; an assertion failure, process crash or timeout does not prevent the remaining cases from running. A failed suite exits with code 1. A skipped case is reported as `SKIP`, with its reason. Real WARP connections, WinDivert interception and the Zarp network adapter are never started.

The cases for your own server (`TestProxy*`, `TestSingBox*`, `TestRouting*`, `TestGeoData*`) use the sing-box embedded by `tools/fetch-singbox.ps1`; without it they report `SKIP`. The XHTTP cases (`TestXray*`) also need the Xray-core embedded by `tools/fetch-xray.ps1` and report `SKIP` without it. They run real sing-box and Xray processes, but only on localhost and without an adapter:

- `TestSingBoxConfigsAccepted` feeds every kind of generated configuration to `sing-box check`, which also rejects invalid RE2 expressions and CIDR ranges.
- `TestSingBoxLoopback[...]` starts a real VLESS, Trojan or Hysteria2 server (with the WebSocket, gRPC and HTTPUpgrade transports where they apply), connects the Zarp client to it and passes TCP and UDP traffic.
- `TestProxyMeasure` runs the connection check of Zarp through a real sing-box probe port: the SOCKS5 login and password, the refusals for a wrong or missing password, the `ip=` field that a genuine `cdn-cgi/trace` answer has, and the start of TLS inside the tunnel. The check page is replaced by a page on localhost.
- `TestProbeClient` feeds the same check, request by request, from a fake SOCKS5 server on localhost: answers with and without length, chunked answers, answers that never end, stubs without `ip=`, error codes, a wrong password, a reset during the handshake, a server that stays silent, cancelling and a server that answers TLS in plain text.
- `TestSingBoxTamper` changes the extracted `sing-box.exe` by one byte and checks that Zarp refuses to start it and that unpacking restores the genuine file.
- `TestRoutingEndToEnd` starts a Trojan server that redirects everything it receives to a marker, so the answer shows whether a connection went through the server or directly. It checks the priority of Block, Proxy and Direct, every kind of rule, GeoIP and GeoSite databases, and the per-app selection by process path (ignoring case).
- `TestSubscriptionParsing`, `TestSubscriptionCache` and `TestLinkExtras` need no network: they read every shape of a subscription answer (base64 in its variants, plain text, JSON, a web page, unsupported and unreadable links, repeated servers, the limit of servers), name and number the servers, keep the saved list per address without the token, and read the parameters that panels add to links (`ech`, `x_padding_bytes`, `support-x25519mlkem768`, the label after `#`). `TestSubscriptionDownloadAsync` feeds scripted answers (redirects, statuses, limits, the second try as another client, cancelling) and `TestSubscriptionRealHttpsAsync` repeats the important ones against a real HTTPS server on localhost with a self-signed certificate (TLS, compression, redirects, endless answers, answers that stall or never start and end at the deadline, an untrusted certificate, a closed port). `TestSubscriptionEngineAsync`, `TestSubscriptionRefreshAsync` and `TestSubscriptionAdoptionAsync` drive the engine with several servers and a fake runtime: the pairs of strategies and servers are searched in order and the best pair is chosen, a failing choice falls back to the next pair, names are resolved once per operation, an old list is refreshed on connect and a failed refresh keeps the old one, the right pair is taken over after a restart. `TestConnectionFormSubscription` covers the window: the status line, the wait while the list loads, the refusals and closing during a load.
- `TestEchIsEnforced`, the `TestSingBoxLoopback[...-ech]` cases and `TestXrayLoopback[tls-ech]` start real servers with ECH keys (sing-box for VLESS, Trojan and Hysteria2, Xray for XHTTP) and check that a link with the right ECH list connects and one with another list does not.
- `TestXhttpProfiles` and `TestXrayConfig` need no process: they check how XHTTP links are parsed (every parameter, what is refused and why, no secret in any message) and the generated configurations of Xray and sing-box (the loopback bridge with its login, the log levels, the rule and the excluded route that keep `xray.exe` out of the adapter, no UUID in the sing-box configuration).
- `TestXrayConfigsAccepted` feeds every kind of XHTTP configuration (none, TLS with pins, Reality with `pqv`, `extra` with `downloadSettings`, IPv6) to `xray run -test` and the bridge side to `sing-box check`, and checks that a bad one is refused with a readable reason (`TestShortenXray` covers the shortening of that reason).
- `TestXrayLoopback[...]` starts a real Xray server with XHTTP (`none`, `packet-up`, `tls-stream-up`, `tls-stream-one`, `tls-extra`, `reality`, `reality-stream-up`; TLS is pinned by the hash of a generated certificate, the Reality target is a sing-box TLS server) and connects the Zarp client to it through the whole chain, the probe port of sing-box and the Xray bridge. TCP, UDP and the connection check pass, the bridge refuses a wrong or missing password, and stopping ends both programs.
- `TestXrayFailureReasons` spoils the link of a working Xray server in the usual ways (certificate pin, UUID, XHTTP path, Reality key and short id) and checks that the check fails and which reason the log shows: the pin, `404` for a wrong path, the Reality errors. A wrong UUID leaves no reason, because the server just closes the connection and Xray logs nothing about it. No reason ever holds the path, the UUID or a page address.
- `TestXrayDiagnostics` checks what a dead server leaves in the log (the reason is shown, the XHTTP path and the page addresses are not, the log is removed on stop) and that the log of a session with the adapter holds no addresses. `TestXrayLifecycle` checks the start order and cleanup after a failed start, taking a session over after a restart of Zarp, and a bridge left alone. `TestXrayTamper` changes the extracted `xray.exe` by one byte and checks that it is refused and restored.
- The engine flows for a server (`TestProxyMode*`, `TestXhttpEngineAsync`, the subscription engine cases) replace sing-box and Xray with a fake, and winws2 with a small program that only lives (the engine finds it by its path like the real one), so no driver and no network are involved. They check that winws2 is running with the strategy of the pair whenever sing-box reaches the server, that its configuration names the address and port of that server and nothing else, that it stops with the tunnel, that a lost winws2 is reported, and, with a model of DPI that lets only one combination of a strategy and a server through, that the search finds it. `TestXhttpEngineAsync` covers the Xray preparation (only for XHTTP links), the antivirus question for the Xray folder and a bridge that disappears while sing-box runs.
- `TestServerPairs` checks which strategy suits which server (TLS or QUIC, XHTTP with and without ALPN `h3`), the identity, the name and the order of the pairs. `TestServerTargetArgs` checks the arguments of winws2 for a server (the port, both directions of the address, IPv4, IPv6, the local network and this computer, a refusal of anything that is not an IP address). `TestServerTargetFilters` asks the real `winws2` for the WinDivert filter it builds (`--wf-save`, which opens nothing and needs no administrator) and lets the real `WinDivert.dll` check its syntax, and `TestServerStrategyDryRun[...]` lets `winws2 --dry-run` verify the arguments of every built-in strategy for a server over IPv4 and IPv6. `TestServerZapretLifecycleAsync` starts, restarts and stops the stand-in winws2 for servers.
- `TestSingBoxLaunchRetry` checks when a launch that the Windows loader killed is repeated (see below). It starts no sing-box.

Built-in strategies have separate cases for each strategy and address restriction setting (and, for a server, for each strategy over IPv4 and IPv6). Log layout cases are separate for every window height limit, scale and size adjustment. Assertions stop the affected case; later independent cases still run.

## Reading failures

The console prints `[RUN]`, `[PASS]`, `[FAIL]` or `[SKIP]` with the test name, parameters and duration, then a final list of failures. GitHub Actions also adds source annotations and a summary. The `zarp-test-results` artifact is uploaded after failures; test failures still fail the job and prevent publishing a release.

With the command above, reports are in `build/test-results`:

- `summary.md`: totals, failure details, skip reasons and every completed case.
- `results.xml`: JUnit report for the current run.
- `selected-tests.txt` and `current-test.txt`: selected cases and the active case if the job is interrupted.
- Dated run directories: environment, per-case results, stdout, stderr and process diagnostics.
- Strategy cases: `zarp.cfg` and `winws2.txt`, including the command, exit code in decimal and hex, timeout flag, stdout/stderr (explicitly marked when empty), embedded zapret2 version and binary SHA-256 hashes.
- UI image cases: PNG captures next to their case results.
- Windows in the cases are shown offscreen and never activated (`WS_EX_NOACTIVATE`, set in `PositionOffscreen`). An activated test window takes over the foreground, so keys typed in another window while the suite runs would vanish into it and show up as a stray character in a text box.
- Test data: every case works in its own `test-data\<id>` folder next to `Zarp.Tests.exe` (the path is printed after `Test data:` in the case output) with its own unpacked copies of zapret2, sing-box and Xray, tens of megabytes each. A passing or skipped case deletes its folder, a failed case keeps it for inspection, and the next run removes the folders that are older than a day.

Reports are updated after every completed case. Writing a report is retried a few times if a virus scanner holds the file for a moment. Default case timeout is 120 seconds; winws2 option parsing has a 30-second timeout. No failing case is automatically retried or turned into a pass.

The one exception is a launch that the Windows loader kills: exit code `0xC0000142` (`STATUS_DLL_INIT_FAILED`) with no output and no timeout. The program never read its arguments, and on GitHub runners this now and then happens to a winws2 strategy case whatever its configuration. Such a launch is repeated, up to 4 launches in total (`TestLoaderRetry` covers the rules). The case still fails if the last launch dies the same way. Every launch is kept in `winws2.txt`, and a case that passed after a repeat adds a `::warning` annotation to the run, so the repeats stay visible. Any other exit code, any output, a timeout or a start error is final. The same rule covers the sing-box and Xray processes of the server cases, the `check` and `-test` runs and the localhost servers (`TestSingBoxLaunchRetry` covers the rules). The Zarp client is started through `cmd`, which hides the exit code, so a client that ends without writing a line to its log counts as killed, and a real error always leaves a line. The repeat is written to the case output and raises the same `::warning`.

## Manual test with the real adapter

Everything above runs on localhost and never creates the `Zarp` network adapter or starts WinDivert. What it cannot show is whether, with the real adapter, the connection of `xray.exe` (or `sing-box.exe`) to your server stays outside the adapter instead of coming back into it, and whether the real `winws2` runs with the strategy of the chosen pair next to the adapter. `TestRealAdapterAsync` checks exactly that, on your computer, with your server. A normal run reports it as `SKIP`; it starts only when `ZARP_REAL_ADAPTER_LINK` is set, from an administrator PowerShell, when no other VPN is on and no other winws, winws2 or GoodbyeDPI runs (it never switches anything off, it refuses to run instead). Turn your VPN off yourself, then:

```powershell
$env:ZARP_REAL_ADAPTER_LINK = 'vless://...'   # the link of your server, or the https:// address of your subscription, as in Zarp
.\build\tests\Zarp.Tests.exe --run-test TestRealAdapterAsync --artifacts build/real
Remove-Item Env:ZARP_REAL_ADAPTER_LINK
```

`--run-test` runs the case in this very process, so the `[manual]` progress lines appear on the screen as they happen (the usual `--filter` run prints only PASS or FAIL and keeps the lines in `stdout.txt` of the case folder). The exit code is 1 only if a check failed; a refusal to run (VPN on, not an administrator) prints its reason and exits with 0.

It reads your public address, searches the pairs of a zapret2 strategy and your server with the real engine and the real `winws2` (the first pair that passes twice wins; the check without the adapter first, then the adapter), and then checks that the `Zarp` adapter is up, that `winws2` runs with the strategy of the chosen pair and intercepts the address and the port of the server, that a request goes through the tunnel (and whether the exit address changed), that the TCP connection of Xray (or sing-box) to the server leaves through your real network interface and not through `Zarp`, that DNS works, that the tunnel stays up for 20 seconds and that disconnecting removes the adapter and all the programs (winws2 included) and brings the direct address back. With a subscription the list is loaded first, while the network is still plain, and the search covers all its servers as it would for you. The link, the subscription address and the addresses of the servers are never printed, and the saved settings and the saved list of servers are deleted afterwards. The case lasts about a minute when the first strategies pass; a server that no strategy helps keeps it busy until the search ends, and the network blinks while the adapter is created and removed. If something goes wrong, a watchdog stops the tunnel and winws2 after 14 minutes at the latest. If the test process is killed anyway, open Zarp and press Disconnect, or end `sing-box.exe`, `xray.exe` and `winws2.exe` that run from a `test-data` folder.

`TestTcpTable` checks on localhost the table of TCP connections that this test reads.

## Running selected cases

```powershell
.\build\tests\Zarp.Tests.exe --list
.\build\tests\Zarp.Tests.exe --filter 'warp-t-multidisorder,restrict=False' --results build/strategy-results
.\build\tests\Zarp.Tests.exe --filter 'TestLogLayout[limit=749,scale=1.5,adjustment=7]' --results build/layout-results
```

The filter matches a case-insensitive substring. A filter matching no cases exits with an error.

`TestRunnerReporting` verifies the reporting mechanism with deliberate assertion failures, a process exit without a result, a timeout, a skip and a passing case after them. Its nested `expected failures with spaces` directory contains those intentional failures; the root `results.xml` contains the actual suite results.

`tools/fetch-zapret.ps1` supplies the embedded zapret2 used by native strategy cases. If the archive was absent at build time, those cases explicitly report `SKIP`. A present binary that cannot start or verify its configuration is a failure with process diagnostics.
