use serde::Serialize;
use sysinfo::{Disks, System};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capacity {
    total_bytes: String,
    available_bytes: String,
}
fn capacity(total: u64, available: u64) -> Option<Capacity> {
    (total > 0 && available <= total && total <= i64::MAX as u64).then(|| Capacity {
        total_bytes: total.to_string(),
        available_bytes: available.to_string(),
    })
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cpu {
    model: String,
    logical_processors: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    schema_version: u8,
    cpu: Option<Cpu>,
    memory: Option<Capacity>,
    system_disk: Option<Capacity>,
    uptime_seconds: Option<String>,
}

pub fn collect() -> Inventory {
    let mut system = System::new().ok();
    if let Some(value) = system.as_mut() {
        value.refresh_memory();
        value.refresh_cpu_all();
    }
    let cpu = system.as_ref().and_then(|value| {
        let cpus = value.cpus();
        (1..=65536).contains(&cpus.len()).then(|| Cpu {
            model: cpus[0]
                .brand()
                .chars()
                .filter(|ch| !ch.is_control())
                .take(200)
                .collect::<String>()
                .trim()
                .into(),
            logical_processors: cpus.len(),
        })
    });
    #[cfg(target_os = "windows")]
    let root = std::path::PathBuf::from(format!(
        "{}\\",
        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
    ));
    #[cfg(not(target_os = "windows"))]
    let root = std::path::PathBuf::from("/");
    let disks = Disks::new_with_refreshed_list().ok();
    let disk = disks
        .as_ref()
        .and_then(|value| value.iter().find(|disk| disk.mount_point() == root));
    Inventory {
        schema_version: 1,
        cpu,
        memory: system
            .as_ref()
            .and_then(|value| capacity(value.total_memory(), value.available_memory())),
        system_disk: disk.and_then(|disk| capacity(disk.total_space(), disk.available_space())),
        uptime_seconds: System::uptime()
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .map(|value| value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_preserves_exact_bytes_and_unknown_is_not_zero() {
        assert!(capacity(0, 0).is_none());
        assert!(capacity(4, 5).is_none());
        let value = capacity(9007199254740993, 0).unwrap();
        assert_eq!(value.total_bytes, "9007199254740993");
        assert_eq!(value.available_bytes, "0");
    }
    #[test]
    fn actual_host_collection_is_bounded_and_contains_no_paths_or_credentials() {
        let value = serde_json::to_value(collect()).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert!(value["cpu"]["logicalProcessors"].as_u64().unwrap() > 0);
        assert!(
            value["memory"]["totalBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(!value.to_string().contains("mountPoint"));
    }
}
