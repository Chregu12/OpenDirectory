# OpenDirectory Agent

This archive contains the native agent and its source/binary manifest. Match the platform and architecture before use. The source revision, SHA-256 and GitHub build-provenance attestation identify the build. An attestation is not Apple Developer ID/notarization or Windows Authenticode; OS code signing is not configured in this release.

Verify the archive with GitHub CLI before extracting or running it:

```sh
gh attestation verify ARCHIVE --repo Chregu12/OpenDirectory --signer-workflow Chregu12/OpenDirectory/.github/workflows/agent.yml --source-ref refs/tags/agent-v1.5.0 --deny-self-hosted-runners
```

Server/gateway 1.0.48 or later is required. Linux GNU packages require glibc 2.39 or later and the OpenSSL 3 runtime libraries. macOS packages are separate for Apple Silicon and Intel. Windows x64 uses the system TLS stack. Private CA certificates must stay available for the installed service; do not disable TLS validation.

Create a one-time enrollment code for the correct inventory device in OpenDirectory. From an administrator terminal, enroll with the actual server URL, using `OD_ENROLLMENT_TOKEN` from a hidden prompt. Never put the code into a literal command or log. `OD_CA_CERT` selects a private CA file when needed. On Unix, use a root-owned protected configuration and CA path. On Windows, keep both inside `%PROGRAMDATA%\OpenDirectory`.

```sh
# Linux/macOS: run in a root shell; enter the code without echo.
read -r -s OD_ENROLLMENT_TOKEN
export OD_ENROLLMENT_TOKEN
./od-agent-service --server-url https://YOUR-SERVER enroll
unset OD_ENROLLMENT_TOKEN
./od-agent-service install --dry-run
./od-agent-service install
```

```powershell
# Windows: elevated PowerShell.
$code = Read-Host 'One-time enrollment code' -AsSecureString
$env:OD_ENROLLMENT_TOKEN = [System.Net.NetworkCredential]::new('', $code).Password
.\od-agent-service.exe --server-url https://YOUR-SERVER enroll
Remove-Item Env:OD_ENROLLMENT_TOKEN
.\od-agent-service.exe install --dry-run
.\od-agent-service.exe install
```

`install` copies the executable into its protected OS location and registers/starts systemd, LaunchDaemon, or a SYSTEM scheduled task. It uses the saved enrollment, not temporary endpoint/credential overrides. `--config-path ABSOLUTE-PATH` selects the same file for foreground and service operation. Existing different service definitions are refused; `install --replace-existing` explicitly preserves a backup before replacement. Installation failure is reported as failure; inspect the native manager before retrying. Reinstalling the same definition supports updates without overwriting the saved enrollment.

A running process does not prove successful server authentication. Check the actual device connection in OpenDirectory. To stop/uninstall, use the native service manager (`systemctl disable --now od-agent`, `launchctl bootout system/com.opendirectory.agent`, or stop/unregister `OpenDirectoryAgent`). Remove the known service definition and executable after stopping. Credential revocation remains a separate authorized action in OpenDirectory; removing local files does not revoke it. Keep credential files private.
