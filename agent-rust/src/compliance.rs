use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{timeout, Duration},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    state: String,
    reason: String,
}
impl Check {
    fn known(enabled: bool) -> Self {
        Self {
            state: if enabled { "enabled" } else { "disabled" }.into(),
            reason: "checked".into(),
        }
    }
    fn unknown(reason: &str) -> Self {
        Self {
            state: "unknown".into(),
            reason: reason.into(),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Security {
    schema_version: u8,
    os_version: Option<String>,
    disk_encryption: Check,
    firewall: Check,
}
async fn probe(path: &str, args: &[&str]) -> Result<String, &'static str> {
    let mut child = Command::new(path)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "probe-failed")?;
    let stdout = child.stdout.take().ok_or("probe-failed")?;
    let result = timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        stdout
            .take(65537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "probe-failed")?;
        if bytes.len() > 65536 {
            return Err("unrecognized");
        }
        if !child.wait().await.map_err(|_| "probe-failed")?.success() {
            return Err("probe-failed");
        }
        String::from_utf8(bytes).map_err(|_| "unrecognized")
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            match other {
                Ok(Err(reason)) => Err(reason),
                _ => Err("timeout"),
            }
        }
    }
}
fn numeric_version(value: String) -> Option<String> {
    let parts: Vec<_> = value.split('.').collect();
    (parts.len() <= 4
        && !parts.is_empty()
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 6 && part.bytes().all(|ch| ch.is_ascii_digit())
        }))
    .then_some(value)
}
#[cfg(any(test, target_os = "macos"))]
fn filevault(value: &str) -> Check {
    match value.trim() {
        "FileVault is On." => Check::known(true),
        "FileVault is Off." => Check::known(false),
        _ => Check::unknown("unrecognized"),
    }
}
#[cfg(any(test, target_os = "macos"))]
fn mac_firewall(value: &str) -> Check {
    match value.trim() {
        "Firewall is disabled. (State = 0)" => Check::known(false),
        "Firewall is enabled. (State = 1)"
        | "Firewall is set to block all non-essential incoming connections. (State = 2)" => {
            Check::known(true)
        }
        _ => Check::unknown("unrecognized"),
    }
}
#[cfg(any(test, target_os = "linux"))]
fn ufw(value: &str) -> Check {
    match value.lines().next().map(str::trim) {
        Some("Status: active") => Check::known(true),
        Some("Status: inactive") => Check::known(false),
        _ => Check::unknown("unrecognized"),
    }
}
#[cfg(any(test, target_os = "linux"))]
fn encrypted_root(value: &serde_json::Value, encrypted: bool) -> Option<bool> {
    let kind = value.get("type")?.as_str()?;
    if encrypted || kind == "crypt" {
        return Some(true);
    }
    match value.get("children") {
        Some(children) => {
            let children = children.as_array()?;
            if children.is_empty() {
                return None;
            }
            let results: Vec<_> = children
                .iter()
                .map(|child| encrypted_root(child, false))
                .collect();
            if results.contains(&Some(false)) {
                Some(false)
            } else if results.iter().all(|value| *value == Some(true)) {
                Some(true)
            } else {
                None
            }
        }
        None => {
            if ["disk", "part"].contains(&kind) {
                Some(false)
            } else {
                None
            }
        }
    }
}
#[cfg(any(test, target_os = "linux"))]
fn root_device(value: &str) -> Option<&str> {
    let parts: Vec<_> = value.split_whitespace().collect();
    // Multi-device filesystems need a separate complete-device resolver.
    if parts.len() != 2
        || !["ext2", "ext3", "ext4", "xfs"].contains(&parts[1])
        || !parts[0].starts_with("/dev/")
    {
        return None;
    }
    Some(parts[0])
}
#[cfg(target_os = "linux")]
async fn linux_encryption() -> Check {
    let source = match probe(
        "/usr/bin/findmnt",
        &["--noheadings", "--output", "SOURCE,FSTYPE", "--target", "/"],
    )
    .await
    {
        Ok(value) => value,
        Err(reason) => return Check::unknown(reason),
    };
    let device = match root_device(&source) {
        Some(value) => value,
        None => return Check::unknown("not-supported"),
    };
    let value = match probe(
        "/usr/bin/lsblk",
        &["--json", "--inverse", "--output", "NAME,TYPE", device],
    )
    .await
    {
        Ok(value) => value,
        Err(reason) => return Check::unknown(reason),
    };
    let nodes = serde_json::from_str::<serde_json::Value>(&value).ok();
    let nodes = nodes
        .as_ref()
        .and_then(|value| value["blockdevices"].as_array());
    match nodes
        .filter(|nodes| nodes.len() == 1)
        .and_then(|nodes| encrypted_root(&nodes[0], false))
    {
        Some(value) => Check::known(value),
        None => Check::unknown("unrecognized"),
    }
}
#[cfg(target_os = "windows")]
async fn windows_check(script: &str) -> Check {
    let path = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
    )
    .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let value = match probe(
        &path.to_string_lossy(),
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
    )
    .await
    {
        Ok(value) => value,
        Err(reason) => return Check::unknown(reason),
    };
    serde_json::from_str::<Check>(value.trim_start_matches('\u{feff}').trim())
        .ok()
        .filter(|value| {
            ["enabled", "disabled"].contains(&value.state.as_str()) && value.reason == "checked"
        })
        .unwrap_or_else(|| Check::unknown("unrecognized"))
}
pub async fn collect() -> Security {
    #[cfg(target_os = "macos")]
    let (disk, firewall) = tokio::join!(
        probe("/usr/bin/fdesetup", &["status"]),
        probe(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"]
        )
    );
    #[cfg(target_os = "macos")]
    let (disk_encryption, firewall) = (
        disk.map(|value| filevault(&value))
            .unwrap_or_else(Check::unknown),
        firewall
            .map(|value| mac_firewall(&value))
            .unwrap_or_else(Check::unknown),
    );
    #[cfg(target_os = "linux")]
    let (disk_encryption, firewall) = {
        let (disk, firewall) =
            tokio::join!(linux_encryption(), probe("/usr/sbin/ufw", &["status"]));
        (
            disk,
            firewall
                .map(|value| ufw(&value))
                .unwrap_or_else(Check::unknown),
        )
    };
    #[cfg(target_os = "windows")]
    let (disk_encryption, firewall) = tokio::join!(
        windows_check("$ErrorActionPreference='Stop';$v=Get-BitLockerVolume -MountPoint ([IO.Path]::GetPathRoot([Environment]::SystemDirectory));$s=$v.VolumeStatus.ToString();$p=$v.ProtectionStatus.ToString();if($s -eq 'FullyEncrypted' -and $p -eq 'On'){@{state='enabled';reason='checked'}|ConvertTo-Json -Compress}elseif($s -eq 'FullyDecrypted' -or $p -eq 'Off'){@{state='disabled';reason='checked'}|ConvertTo-Json -Compress}else{exit 1}"),
        windows_check("$ErrorActionPreference='Stop';$p=@(Get-NetFirewallProfile -PolicyStore ActiveStore);if($p.Count -ne 3){exit 1};$s=@($p|ForEach-Object{$_.Enabled.ToString()});if(@($s|Where-Object{$_ -ne 'True' -and $_ -ne 'False'}).Count){exit 1};$v=if($s -contains 'False'){'disabled'}else{'enabled'};@{state=$v;reason='checked'}|ConvertTo-Json -Compress")
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let (disk_encryption, firewall) = (
        Check::unknown("not-supported"),
        Check::unknown("not-supported"),
    );
    Security {
        schema_version: 1,
        os_version: sysinfo::System::os_version().ok().and_then(numeric_version),
        disk_encryption,
        firewall,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inactive_firewall_and_unrecognized_probe_do_not_pass() {
        assert_eq!(ufw("Status: inactive\n").state, "disabled");
        assert_eq!(ufw("Status: active\n").state, "enabled");
        assert_eq!(ufw("permission denied").state, "unknown");
        assert_eq!(filevault("FileVault is On.").state, "enabled");
        assert_eq!(filevault("Encryption in progress").state, "unknown");
        assert_eq!(
            mac_firewall("Firewall is disabled. (State = 0)").state,
            "disabled"
        );
    }
    #[test]
    fn every_root_dependency_must_be_encrypted() {
        let value = serde_json::json!({"type":"lvm","children":[{"type":"crypt","children":[{"type":"disk"}]},{"type":"part"}]});
        assert_eq!(encrypted_root(&value, false), Some(false));
        assert_eq!(
            encrypted_root(
                &serde_json::json!({"type":"lvm","children":[{"type":"crypt"}]}),
                false
            ),
            Some(true)
        );
        assert_eq!(
            encrypted_root(&serde_json::json!({"type":"overlay"}), false),
            None
        );
    }
    #[test]
    fn unsupported_multi_device_root_never_confirms_encryption() {
        assert_eq!(
            root_device("/dev/mapper/root ext4\n"),
            Some("/dev/mapper/root")
        );
        assert_eq!(root_device("/dev/mapper/root btrfs\n"), None);
        assert_eq!(root_device("overlay overlay\n"), None);
        assert_eq!(root_device("/dev/a ext4\n/dev/b ext4"), None);
    }
    #[test]
    fn os_version_requires_real_numeric_components() {
        assert!(numeric_version("22.04".into()).is_some());
        assert!(numeric_version("Linux unknown".into()).is_none());
    }
    #[tokio::test]
    async fn failing_probe_is_unknown_without_leaking_output() {
        assert_eq!(
            probe("/not/an/executable", &[]).await.unwrap_err(),
            "probe-failed"
        );
    }
}
