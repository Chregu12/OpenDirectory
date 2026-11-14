use crate::config::AgentConfig;
use serde::Serialize;
use std::path::{Path, PathBuf};
type Error = Box<dyn std::error::Error>;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    platform: &'static str,
    executable: PathBuf,
    config: PathBuf,
    service: PathBuf,
}
fn path_text(path: &Path) -> Result<&str, Error> {
    let value = path.to_str().ok_or("Service paths must be Unicode")?;
    if !path.is_absolute() || value.chars().any(|value| value.is_control()) {
        return Err("Absolute service paths without control characters required".into());
    }
    Ok(value)
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn systemd(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}
fn definition(plan: &Plan) -> Result<String, Error> {
    let (executable, config) = (path_text(&plan.executable)?, path_text(&plan.config)?);
    if plan.platform == "linux" {
        Ok(format!("[Unit]\nDescription=OpenDirectory device agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} --config-path {} run\nRestart=always\nRestartSec=10\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n",systemd(executable),systemd(config)))
    } else {
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.opendirectory.agent</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--config-path</string><string>{}</string><string>run</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>Umask</key><integer>63</integer>\n</dict></plist>\n",xml(executable),xml(config)))
    }
}
fn plan(config: PathBuf) -> Result<Plan, Error> {
    path_text(&config)?;
    let (executable, service) = if cfg!(target_os = "macos") {
        (
            PathBuf::from("/Library/Application Support/OpenDirectory/bin/od-agent-service"),
            PathBuf::from("/Library/LaunchDaemons/com.opendirectory.agent.plist"),
        )
    } else if cfg!(target_os = "linux") {
        (
            PathBuf::from("/usr/local/lib/opendirectory/od-agent-service"),
            PathBuf::from("/etc/systemd/system/od-agent.service"),
        )
    } else if cfg!(target_os = "windows") {
        (
            PathBuf::from(
                std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
            )
            .join("OpenDirectory/Agent/od-agent-service.exe"),
            PathBuf::from("OpenDirectoryAgent"),
        )
    } else {
        return Err("Service installation is unsupported on this platform".into());
    };
    Ok(Plan {
        platform: std::env::consts::OS,
        executable,
        config,
        service,
    })
}
pub fn preview(config: PathBuf) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(&plan(config)?)?);
    Ok(())
}

pub fn install(cfg: &AgentConfig, dry_run: bool, replace_existing: bool) -> Result<(), Error> {
    let plan = plan(cfg.path())?;
    if dry_run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    let bytes = std::fs::read(&plan.config)?;
    if bytes.len() > 65536 {
        return Err("Saved agent configuration is too large".into());
    }
    let saved: AgentConfig = serde_json::from_slice(&bytes)?;
    if serde_json::to_value(&saved)? != serde_json::to_value(cfg)? {
        return Err("Install requires the saved enrollment; transient URL, credential or CA overrides are not installed".into());
    }
    crate::enrollment::client(&saved)?;
    if !saved
        .device_id
        .as_deref()
        .is_some_and(crate::enrollment::device_id)
        || !saved
            .device_token
            .as_deref()
            .is_some_and(|value| crate::enrollment::token(value, "odad_"))
    {
        return Err("Enroll the device before installing its service".into());
    }
    if let Some(path) = &saved.ca_cert_path {
        path_text(Path::new(path))?;
    }
    #[cfg(unix)]
    unix_install(&plan, replace_existing)?;
    #[cfg(windows)]
    windows_install(&plan, replace_existing)?;
    println!("OpenDirectory agent installed and running. Confirm the actual device connection in OpenDirectory.");
    Ok(())
}
#[cfg(unix)]
fn secure(path: &Path, credential: bool) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & (if credential { 0o077 } else { 0o022 }) != 0
    {
        return Err(format!("Root-owned protected path required: {}", path.display()).into());
    }
    if credential && !metadata.is_file() {
        return Err("Regular private configuration required".into());
    }
    Ok(())
}
#[cfg(unix)]
fn parents(path: &Path) -> Result<(), Error> {
    for parent in path.ancestors() {
        secure(parent, false)?;
    }
    Ok(())
}
#[cfg(unix)]
fn directory(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path)?;
    }
    parents(path)
}
#[cfg(unix)]
fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), Error> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
#[cfg(unix)]
fn manager(program: &str, args: &[&str]) -> Result<std::process::Output, Error> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Service manager timed out".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "Service manager failed: {} {} ({})",
            program,
            args.first().copied().unwrap_or(""),
            output.status
        )
        .into());
    }
    Ok(output)
}
#[cfg(unix)]
fn unix_install(plan: &Plan, replace: bool) -> Result<(), Error> {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    if unsafe { geteuid() } != 0 {
        return Err("Run install as root after reviewing install --dry-run".into());
    }
    secure(&plan.config, true)?;
    parents(plan.config.parent().ok_or("Config parent missing")?)?;
    let saved: AgentConfig = serde_json::from_slice(&std::fs::read(&plan.config)?)?;
    if let Some(path) = saved.ca_cert_path {
        secure(Path::new(&path), false)?;
        parents(Path::new(&path).parent().ok_or("CA parent missing")?)?;
    }
    let content = definition(plan)?;
    let exists = plan.service.exists();
    if exists {
        secure(&plan.service, false)?;
        if std::fs::read(&plan.service)? != content.as_bytes() && !replace {
            return Err("Different service configuration exists; review it and explicitly use --replace-existing to back it up and replace it".into());
        }
    }
    directory(
        plan.executable
            .parent()
            .ok_or("Install directory missing")?,
    )?;
    parents(plan.service.parent().ok_or("Service directory missing")?)?;
    if plan.executable.exists() {
        secure(&plan.executable, false)?;
    }
    if exists && std::fs::read(&plan.service)? != content.as_bytes() {
        let backup = plan
            .executable
            .parent()
            .unwrap()
            .join(format!("previous-service-{}.backup", uuid::Uuid::new_v4()));
        write(&backup, &std::fs::read(&plan.service)?, 0o600)?;
        println!(
            "Previous service definition retained at {}",
            backup.display()
        );
    }
    if plan.platform == "linux" && exists {
        manager("/usr/bin/systemctl", &["daemon-reload"])?;
        manager("/usr/bin/systemctl", &["stop", "od-agent.service"])?;
    }
    if plan.platform == "macos" {
        let loaded = std::process::Command::new("/bin/launchctl")
            .args(["print", "system/com.opendirectory.agent"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?
            .success();
        if loaded && !exists && !replace {
            return Err(
                "A service with this label already exists; explicit replacement required".into(),
            );
        }
        if loaded {
            manager(
                "/bin/launchctl",
                &["bootout", "system/com.opendirectory.agent"],
            )?;
        }
    }
    let source = std::env::current_exe()?;
    if source != plan.executable {
        write(&plan.executable, &std::fs::read(source)?, 0o755)?;
    }
    write(&plan.service, content.as_bytes(), 0o644)?;
    if plan.platform == "linux" {
        manager("/usr/bin/systemctl", &["daemon-reload"])?;
        manager(
            "/usr/bin/systemctl",
            &["enable", "--now", "od-agent.service"],
        )?;
        manager(
            "/usr/bin/systemctl",
            &["is-active", "--quiet", "od-agent.service"],
        )?;
    } else {
        manager(
            "/bin/launchctl",
            &["bootstrap", "system", path_text(&plan.service)?],
        )?;
        let mut running = false;
        for _ in 0..20 {
            let output = manager(
                "/bin/launchctl",
                &["print", "system/com.opendirectory.agent"],
            )?;
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim().starts_with("pid = "))
            {
                running = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if !running {
            return Err(
                "LaunchDaemon registered but no running agent process was confirmed".into(),
            );
        }
    }
    Ok(())
}
#[cfg(windows)]
fn windows_install(plan: &Plan, replace: bool) -> Result<(), Error> {
    let options = serde_json::json!({"source":std::env::current_exe()?,"config":plan.config,"destination":plan.executable,"replace":replace});
    let script = format!(
        "$Options = ConvertFrom-Json '{}'\n{}",
        options.to_string().replace('\'', "''"),
        include_str!("../install-windows.ps1")
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        encoded.push(TABLE[((value >> 18) & 63) as usize] as char);
        encoded.push(TABLE[((value >> 12) & 63) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    let system =
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()));
    let status =
        std::process::Command::new(system.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded,
            ])
            .status()?;
    if !status.success() {
        return Err("Windows agent task installation did not complete".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn templates_keep_paths_as_data() {
        let plan = Plan {
            platform: "linux",
            executable: PathBuf::from("/opt/agent with spaces/%agent"),
            config: PathBuf::from("/etc/config %one/agent.json"),
            service: PathBuf::from("/etc/systemd/system/od-agent.service"),
        };
        let text = definition(&plan).unwrap();
        assert!(text.contains("ExecStart=\"/opt/agent with spaces/%%agent\" --config-path \"/etc/config %%one/agent.json\" run"));
        let plan = Plan {
            platform: "macos",
            executable: PathBuf::from("/Library/A&B/agent"),
            config: PathBuf::from("/Library/A<B/config.json"),
            service: PathBuf::from("/Library/job.plist"),
        };
        let text = definition(&plan).unwrap();
        assert!(text.contains("A&amp;B"));
        assert!(text.contains("A&lt;B"));
        assert!(text.contains("--config-path"));
    }
    #[test]
    fn relative_and_control_paths_are_rejected() {
        assert!(plan(PathBuf::from("relative.json")).is_err());
        assert!(plan(PathBuf::from("/etc/agent\n.json")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn user_owned_paths_do_not_become_root_services() {
        let path = std::env::temp_dir().join(format!("od-install-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "not a credential").unwrap();
        if unsafe { geteuid_for_test() } != 0 {
            assert!(secure(&path, true).is_err());
        }
        std::fs::remove_file(path).unwrap();
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe fn geteuid_for_test() -> u32 {
            unsafe { geteuid() }
        }
    }
}
