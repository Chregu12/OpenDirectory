use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn request(input: &str) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opendirectory-connectors"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn invalid_write() -> Value {
    // This deliberately invalid bearer fails before creating an HTTP client.
    json!({"operation":"microsoft.assignLicense","accessToken":"private fixture",
        "objectId":"11111111-1111-4111-8111-111111111111",
        "skuId":"22222222-2222-4222-8222-222222222222","disabledPlans":[],
        "desired":true,"attemptId":"33333333-3333-4333-8333-333333333333"})
}

#[test]
fn the_actual_binary_keeps_read_errors_compatible_and_marks_preflight_write_rejection() {
    let read = json!({"operation":"microsoft.user","accessToken":"private fixture",
        "objectId":"11111111-1111-4111-8111-111111111111"});
    assert_eq!(
        request(&read.to_string()),
        json!({"ok":false,"code":"graph_read_invalid_request"})
    );
    assert_eq!(
        request(&invalid_write().to_string()),
        json!({"ok":false,"code":"graph_write_invalid_request","uncertain":false})
    );
}

#[test]
fn writes_require_every_typed_field_and_reject_caller_controlled_endpoints() {
    let valid = invalid_write();
    for field in [
        "accessToken",
        "objectId",
        "skuId",
        "disabledPlans",
        "desired",
        "attemptId",
    ] {
        let mut data = valid.clone();
        data.as_object_mut().unwrap().remove(field);
        assert_eq!(
            request(&data.to_string()),
            json!({"ok":false,"code":"graph_capacity_invalid_request"})
        );
    }
    for (field, value) in [
        ("url", json!("https://untrusted.invalid")),
        ("origin", json!("http://127.0.0.1")),
        ("desired", json!("true")),
        ("disabledPlans", Value::Null),
    ] {
        let mut data = valid.clone();
        data[field] = value;
        assert_eq!(
            request(&data.to_string()),
            json!({"ok":false,"code":"graph_capacity_invalid_request"})
        );
    }
}

#[test]
fn only_writes_get_the_larger_bounded_envelope_for_tokens_and_plans() {
    let read = format!(
        "{}{}",
        " ".repeat(20_001),
        json!({"operation":"microsoft.user","accessToken":"private fixture","objectId":"11111111-1111-4111-8111-111111111111"})
    );
    assert_eq!(
        request(&read),
        json!({"ok":false,"code":"graph_capacity_invalid_request"})
    );
    let mut write = invalid_write();
    write["accessToken"] = json!(format!("{} ", "t".repeat(16_382)));
    write["disabledPlans"] = json!((0..128)
        .map(|i| format!("00000000-0000-4000-8000-{i:012x}"))
        .collect::<Vec<_>>());
    let encoded = write.to_string();
    assert!(encoded.len() > 20_000 && encoded.len() <= 32_768);
    assert_eq!(
        request(&encoded),
        json!({"ok":false,"code":"graph_write_invalid_request","uncertain":false})
    );
    assert_eq!(
        request(&format!("{}{}", " ".repeat(32_769), encoded)),
        json!({"ok":false,"code":"graph_capacity_invalid_request"})
    );
}
