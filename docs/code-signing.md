# Signing Zarp for Windows

The "Unknown publisher" warning means that `Zarp.exe` does not have a trusted Authenticode signature. The company name in the EXE properties, a SHA-256 hash and a GitHub attestation are not substitutes for that signature.

A signature identifies the publisher, but does not guarantee that SmartScreen warnings disappear immediately: Microsoft evaluates application reputation separately. This applies to OV and EV certificates as well as Azure Artifact Signing. See [Microsoft's explanation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options).

## GitHub Releases: SignPath

The workflow supports SignPath, but **publishes unsigned releases by default**. A missing certificate or missing secrets do not prevent the build. The release notes explicitly state whether the EXE is signed. Branch and pull request builds remain unsigned test artifacts.

Enable signing by setting the repository variable `SIGNPATH_ENABLED=true`. Once signing is enabled, configuration or signature verification errors stop the release: the workflow does not fall back to an unsigned EXE if the signing service fails.

1. Create a project in SignPath. Open-source projects can [apply to the SignPath Foundation](https://signpath.org/apply). Free signing is subject to review under the [program terms](https://signpath.org/terms); approval for Zarp is not guaranteed. Explain the application's purpose and disclose that it includes zapret2/WinDivert. If you use a Foundation certificate, the publisher will be SignPath Foundation.
2. Connect the `feg55/Zarp` repository to the SignPath GitHub integration. Configure the project and release signing policy with a trusted certificate and timestamping. A self-signed test certificate will not pass release verification.
3. Set [signpath-artifact.xml](signpath-artifact.xml) as the default artifact configuration. GitHub supplies a ZIP with `Zarp.exe` at its root. This configuration signs the outer EXE; it does not add signatures to embedded third-party files.
4. In GitHub → Settings → Secrets and variables → Actions, add:

   | Type | Name | Value |
   | --- | --- | --- |
   | Secret | `SIGNPATH_API_TOKEN` | Token with permission to submit signing requests |
   | Variable | `SIGNPATH_ORGANIZATION_ID` | SignPath organization ID |
   | Variable | `SIGNPATH_PROJECT_SLUG` | Project slug |
   | Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | Release signing policy slug |
   | Variable | `SIGNPATH_ENABLED` | `true` — enable signing after configuring the other values |

5. Restrict the signing policy to your repository, release workflow and trusted tag authors. If the service requires request approval, approve it in SignPath; the workflow waits up to 10 minutes for completion. After your application is approved, meet the Foundation's requirements for the project page and team roles.
6. After setting `SIGNPATH_ENABLED=true`, create a new version tag. The workflow builds the EXE, submits the artifact for signing, verifies Windows trust and the timestamp, then calculates the SHA-256 hash, creates an attestation and publishes the release. If signing is enabled and fails, an unsigned EXE will not be published to Releases. Until the service is configured, leave `SIGNPATH_ENABLED` unset or set it to `false` to continue publishing unsigned releases.

For integration settings, see the [official SignPath documentation](https://docs.signpath.io/trusted-build-systems/github).

## Signing locally with your own certificate

Build `dist\Zarp.exe` using the usual `build.ps1` script. Install the Windows SDK with SignTool and make your CA-issued certificate or hardware token available through the CurrentUser\My certificate store. Run the following commands from Developer PowerShell, replacing the values in angle brackets:

```powershell
signtool sign /sha1 <THUMBPRINT> /s My /fd SHA256 /tr <RFC3161_TIMESTAMP_URL> /td SHA256 /d Zarp .\dist\Zarp.exe
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
.\tools\verify-signature.ps1 -Path .\dist\Zarp.exe
Get-FileHash .\dist\Zarp.exe -Algorithm SHA256
```

Use your provider's timestamp server. For a certificate in LocalMachine, add `/sm`. The `/sha1` option selects the certificate by its thumbprint; `/fd SHA256` sets the file signature digest algorithm. Keep the private key on the token or in the certificate store, outside the repository. See [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).

Rebuilding overwrites the signature, so sign the final EXE before distributing it. Previously published files do not become signed automatically.

## Verifying the result

```powershell
Get-AuthenticodeSignature .\Zarp.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

Expect `Status: Valid` and a certificate identifying the actual publisher. A newly signed file may still trigger SmartScreen until it builds reputation. For an antivirus false positive, submit the exact file you distribute to [Microsoft for analysis](https://www.microsoft.com/en-us/wdsi/filesubmission). This is a separate process and does not guarantee removal of a reputation warning.

The UAC prompt for administrator rights remains: WinDivert requires elevation, and UAC is separate from SmartScreen. Signing Zarp also does not change how antivirus software classifies WinDivert.
