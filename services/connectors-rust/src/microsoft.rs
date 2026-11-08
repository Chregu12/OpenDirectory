// Independent implementation of Microsoft's subscribedSku API. Connector capability
// separation is informed by Nango and Ampersand; no third-party source is copied.
// https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0
use crate::http::{bearer, client, read_json, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const SELECT: &str = "skuId,skuPartNumber,appliesTo,capabilityStatus,prepaidUnits,consumedUnits";
const PATH: &str = "/v1.0/subscribedSkus";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepaidUnits {
    enabled: i32,
    warning: i32,
    suspended: i32,
    locked_out: i32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sku {
    sku_id: String,
    sku_part_number: String,
    applies_to: String,
    capability_status: String,
    prepaid_units: PrepaidUnits,
    consumed_units: i32,
}

#[derive(Deserialize)]
struct Page {
    value: Vec<Sku>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}

fn continuation(raw: &str, origin: &Url) -> Result<Url, Error> {
    let fail = || Error::new("graph_capacity_invalid_continuation");
    if raw.len() > 4096 {
        return Err(fail());
    }
    let url = Url::parse(raw).map_err(|_| fail())?;
    if url.origin() != origin.origin()
        || url.path() != PATH
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(fail());
    }
    let mut seen = HashSet::new();
    let mut skip = false;
    for (key, value) in url.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err(fail());
        }
        match key.as_ref() {
            "$skiptoken" if !value.is_empty() && value.len() <= 2048 => skip = true,
            "$select" if value == SELECT => {}
            _ => return Err(fail()),
        }
    }
    if !skip {
        return Err(fail());
    }
    Ok(url)
}

fn validate(mut rows: Vec<Sku>) -> Result<Vec<Sku>, Error> {
    let fail = || Error::new("graph_capacity_invalid_response");
    if rows.len() > 1000 {
        return Err(fail());
    }
    let mut seen = HashSet::new();
    for row in &mut rows {
        let parsed = Uuid::parse_str(&row.sku_id).map_err(|_| fail())?;
        if row.sku_id.to_ascii_lowercase() != parsed.hyphenated().to_string()
            || !seen.insert(parsed)
            || row.sku_part_number.trim().is_empty()
            || row.sku_part_number.encode_utf16().count() > 255
            || row.sku_part_number.chars().any(|c| c.is_ascii_control())
            || !["User", "Company"].contains(&row.applies_to.as_str())
            || !["Enabled", "Warning", "Suspended", "Deleted", "LockedOut"]
                .contains(&row.capability_status.as_str())
            || [
                row.prepaid_units.enabled,
                row.prepaid_units.warning,
                row.prepaid_units.suspended,
                row.prepaid_units.locked_out,
                row.consumed_units,
            ]
            .iter()
            .any(|v| *v < 0)
        {
            return Err(fail());
        }
        row.sku_id = parsed.hyphenated().to_string();
    }
    rows.sort_by(|a, b| a.sku_id.cmp(&b.sku_id));
    Ok(rows)
}

fn inspect_with_origin(token: &str, origin: &str) -> Result<Vec<Sku>, Error> {
    if !bearer(token) {
        return Err(Error::new("graph_capacity_invalid_request"));
    }
    let origin = Url::parse(origin).map_err(|_| Error::new("graph_capacity_unavailable"))?;
    let client = client("graph_capacity", Default::default())?;
    let mut next = origin
        .join(PATH)
        .map_err(|_| Error::new("graph_capacity_unavailable"))?;
    next.query_pairs_mut().append_pair("$select", SELECT);
    let started = Instant::now();
    let mut visited = HashSet::new();
    let mut rows = Vec::new();
    loop {
        if started.elapsed() >= Duration::from_secs(10)
            || visited.len() >= 16
            || !visited.insert(next.to_string())
        {
            return Err(Error::new("graph_capacity_incomplete"));
        }
        let raw = read_json(&client, &next, token, "graph_capacity")?;
        let object = raw
            .as_object()
            .ok_or_else(|| Error::new("graph_capacity_invalid_response"))?;
        if object.contains_key("@odata.deltaLink")
            || object
                .get("@odata.nextLink")
                .is_some_and(|v| !v.is_string())
        {
            return Err(Error::new("graph_capacity_invalid_response"));
        }
        let page: Page = serde_json::from_value(raw)
            .map_err(|_| Error::new("graph_capacity_invalid_response"))?;
        if rows.len() + page.value.len() > 1000 {
            return Err(Error::new("graph_capacity_invalid_response"));
        }
        rows.extend(page.value);
        match page.next {
            Some(link) => next = continuation(&link, &origin)?,
            None => break,
        }
    }
    if started.elapsed() >= Duration::from_secs(10) {
        return Err(Error::new("graph_capacity_incomplete"));
    }
    validate(rows)
}

pub fn inspect(token: &str) -> Result<Vec<Sku>, Error> {
    inspect_with_origin(token, "https://graph.microsoft.com")
}

// Read one explicitly bound object, never discover or match users by email.
const USER_SELECT: &str = "id,accountEnabled,assignedLicenses,licenseAssignmentStates";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    account_enabled: bool,
    assigned_licenses: Vec<AssignedLicense>,
    license_assignment_states: Vec<AssignmentState>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignedLicense {
    sku_id: String,
    disabled_plans: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentState {
    sku_id: String,
    disabled_plans: Vec<String>,
    // Missing is not equivalent to an explicitly direct assignment.
    #[serde(deserialize_with = "required_nullable")]
    assigned_by_group: Option<String>,
    state: String,
    #[serde(deserialize_with = "required_nullable")]
    error: Option<String>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(de)
}

fn canonical_id(value: &str) -> Option<String> {
    let parsed = Uuid::parse_str(value).ok()?.hyphenated().to_string();
    (value.to_ascii_lowercase() == parsed).then_some(parsed)
}

fn normalize_plans(values: &mut [String]) -> Result<(), Error> {
    let fail = || Error::new("graph_read_invalid_response");
    if values.len() > 128 {
        return Err(fail());
    }
    for value in values.iter_mut() {
        *value = canonical_id(value).ok_or_else(fail)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(fail());
    }
    Ok(())
}

fn validate_user(raw: serde_json::Value, object_id: &str) -> Result<User, Error> {
    let fail = || Error::new("graph_read_invalid_response");
    // A partial/paged object must never be interpreted as an absent assignment.
    let object = raw.as_object().ok_or_else(fail)?;
    if object
        .keys()
        .any(|key| key.ends_with("@odata.nextLink") || key.ends_with("@odata.deltaLink"))
    {
        return Err(fail());
    }
    let mut user: User = serde_json::from_value(raw).map_err(|_| fail())?;
    user.id = canonical_id(&user.id).ok_or_else(fail)?;
    if user.id != object_id
        || user.assigned_licenses.len() > 512
        || user.license_assignment_states.len() > 1024
    {
        return Err(fail());
    }
    let mut skus = HashSet::new();
    for license in &mut user.assigned_licenses {
        license.sku_id = canonical_id(&license.sku_id).ok_or_else(fail)?;
        normalize_plans(&mut license.disabled_plans)?;
        if !skus.insert(license.sku_id.clone()) {
            return Err(fail());
        }
    }
    let mut sources = HashSet::new();
    for assignment in &mut user.license_assignment_states {
        assignment.sku_id = canonical_id(&assignment.sku_id).ok_or_else(fail)?;
        if let Some(group) = &mut assignment.assigned_by_group {
            *group = canonical_id(group).ok_or_else(fail)?;
        }
        normalize_plans(&mut assignment.disabled_plans)?;
        if !["Active", "ActiveWithError", "Disabled", "Error"].contains(&assignment.state.as_str())
            || assignment
                .error
                .as_ref()
                .is_some_and(|error| error.len() > 255 || error.chars().any(char::is_control))
            || !sources.insert((
                assignment.sku_id.clone(),
                assignment.assigned_by_group.clone(),
            ))
        {
            return Err(fail());
        }
    }
    Ok(user)
}

fn read_user_with_origin(token: &str, object_id: &str, origin: &str) -> Result<User, Error> {
    if !bearer(token) || canonical_id(object_id).as_deref() != Some(object_id) {
        return Err(Error::new("graph_read_invalid_request"));
    }
    let mut url = Url::parse(origin)
        .and_then(|origin| origin.join(&format!("/v1.0/users/{object_id}")))
        .map_err(|_| Error::new("graph_read_unavailable"))?;
    url.query_pairs_mut().append_pair("$select", USER_SELECT);
    validate_user(
        read_json(
            &client("graph_read", Default::default())?,
            &url,
            token,
            "graph_read",
        )?,
        object_id,
    )
}

pub fn read_user(token: &str, object_id: &str) -> Result<User, Error> {
    read_user_with_origin(token, object_id, "https://graph.microsoft.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MAX_BODY;
    use crate::test_http::{response, server};

    fn sku(id: &str) -> String {
        format!(
            r#"{{"skuId":"{id}","skuPartNumber":"BUSINESS","appliesTo":"User","capabilityStatus":"Enabled","prepaidUnits":{{"enabled":10,"warning":0,"suspended":0,"lockedOut":0}},"consumedUnits":3}}"#
        )
    }
    #[test]
    fn reads_and_validates_actual_http_response() {
        let body = format!(
            r#"{{"value":[{}]}}"#,
            sku("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
        );
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &body,
        )]);
        let result = inspect_with_origin("token.value", &origin).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(result[0].sku_id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        assert_eq!(result[0].prepaid_units.enabled, 10);
        assert!(requests[0].starts_with("GET /v1.0/subscribedSkus?"));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer token.value"));
    }

    #[test]
    fn rejects_untrusted_continuations_and_duplicate_queries() {
        let origin = Url::parse("https://graph.microsoft.com").unwrap();
        assert!(continuation(
            "https://evil.example/v1.0/subscribedSkus?$skiptoken=x",
            &origin
        )
        .is_err());
        assert!(continuation(
            "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=x&$skiptoken=y",
            &origin
        )
        .is_err());
        assert!(continuation(
            "https://graph.microsoft.com/v1.0/users?$skiptoken=x",
            &origin
        )
        .is_err());
        assert!(continuation(
            "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=x",
            &origin
        )
        .is_ok());
    }

    #[test]
    fn propagates_throttling_without_exposing_response_body() {
        let (origin, server) = server(vec![response(
            "429 Too Many Requests",
            "Retry-After: 90\r\n",
            "secret",
        )]);
        let error = inspect_with_origin("token.value", &origin).unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code, "graph_capacity_http_429");
        assert_eq!(error.retry_after, Some(90));
    }

    #[test]
    fn rejects_duplicate_skus_and_invalid_bearers() {
        let row = sku("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let body = format!(r#"{{"value":[{row},{row}]}}"#);
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &body,
        )]);
        assert_eq!(
            inspect_with_origin("token.value", &origin)
                .unwrap_err()
                .code,
            "graph_capacity_invalid_response"
        );
        server.join().unwrap();
        assert!(!bearer("bad\nheader"));
        assert!(!bearer("x=y"));
        assert!(!bearer("=="));
    }

    #[test]
    fn rejects_null_delta_and_invalid_continuation_without_reporting_a_snapshot() {
        let (origin, first_server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"value":[],"@odata.deltaLink":null}"#,
        )]);
        assert_eq!(
            inspect_with_origin("token.value", &origin)
                .unwrap_err()
                .code,
            "graph_capacity_invalid_response"
        );
        first_server.join().unwrap();
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"value":[],"@odata.nextLink":null}"#,
        )]);
        assert_eq!(
            inspect_with_origin("token.value", &origin)
                .unwrap_err()
                .code,
            "graph_capacity_invalid_response"
        );
        server.join().unwrap();
    }

    #[test]
    fn follows_a_same_origin_continuation_and_returns_a_complete_sorted_snapshot() {
        let first = format!(
            r#"{{"value":[{}],"@odata.nextLink":"{{ORIGIN}}/v1.0/subscribedSkus?$skiptoken=next"}}"#,
            sku("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        );
        let second = format!(
            r#"{{"value":[{}]}}"#,
            sku("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
        let (origin, server) = server(vec![
            response("200 OK", "Content-Type: application/json\r\n", &first),
            response("200 OK", "Content-Type: application/json\r\n", &second),
        ]);
        let rows = inspect_with_origin("token.value", &origin).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].sku_id.starts_with('a'));
        assert!(requests[1].starts_with("GET /v1.0/subscribedSkus?$skiptoken=next"));
    }

    const OBJECT: &str = "11111111-1111-4111-8111-111111111111";
    const SKU: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    fn user() -> serde_json::Value {
        serde_json::json!({
            "id": OBJECT, "accountEnabled": true, "displayName": "Must not leave the connector",
            "assignedLicenses": [{"skuId": SKU, "disabledPlans": []}],
            "licenseAssignmentStates": [{"skuId": SKU, "disabledPlans": [], "assignedByGroup": null, "state": "Active", "error": null}]
        })
    }

    #[test]
    fn reads_only_the_bound_user_and_preserves_direct_and_inherited_sources() {
        let mut raw = user();
        raw["assignedLicenses"][0]["skuId"] = SKU.to_uppercase().into();
        raw["licenseAssignmentStates"][0]["disabledPlans"] =
            serde_json::json!(["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB", SKU]);
        let mut inherited = raw["licenseAssignmentStates"][0].clone();
        inherited["assignedByGroup"] = OBJECT.into();
        inherited["state"] = "ActiveWithError".into();
        inherited["error"] = "CountViolation".into();
        raw["licenseAssignmentStates"]
            .as_array_mut()
            .unwrap()
            .push(inherited);
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &raw.to_string(),
        )]);
        let result = read_user_with_origin("private.token", OBJECT, &origin).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(&format!("GET /v1.0/users/{OBJECT}?")));
        let url = Url::parse(&format!(
            "{origin}{}",
            requests[0].split_whitespace().nth(1).unwrap()
        ))
        .unwrap();
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            [("$select".into(), USER_SELECT.into())]
        );
        assert_eq!(result.assigned_licenses[0].sku_id, SKU);
        assert_eq!(result.license_assignment_states[0].disabled_plans[0], SKU);
        assert!(result.license_assignment_states[0]
            .assigned_by_group
            .is_none());
        assert_eq!(
            result.license_assignment_states[1]
                .assigned_by_group
                .as_deref(),
            Some(OBJECT)
        );
        assert_eq!(
            result.license_assignment_states[1].error.as_deref(),
            Some("CountViolation")
        );
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("displayName"));
    }

    #[test]
    fn partial_ambiguous_or_wrong_user_state_is_never_absence() {
        let base = user();
        let mut invalid = Vec::new();
        for field in [
            "id",
            "accountEnabled",
            "assignedLicenses",
            "licenseAssignmentStates",
        ] {
            let mut value = base.clone();
            value.as_object_mut().unwrap().remove(field);
            invalid.push(value);
        }
        for field in [
            "skuId",
            "disabledPlans",
            "assignedByGroup",
            "state",
            "error",
        ] {
            let mut value = base.clone();
            value["licenseAssignmentStates"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            invalid.push(value);
        }
        for (field, value) in [
            ("id", serde_json::json!(SKU)),
            ("accountEnabled", serde_json::json!("true")),
            ("assignedLicenses", serde_json::json!(null)),
            ("@odata.nextLink", serde_json::json!("https://evil.test")),
            (
                "licenseAssignmentStates@odata.nextLink",
                serde_json::json!(null),
            ),
        ] {
            let mut raw = base.clone();
            raw[field] = value;
            invalid.push(raw);
        }
        for (field, value) in [
            ("assignedByGroup", serde_json::json!("invalid")),
            ("state", serde_json::json!("Pending")),
            ("error", serde_json::json!("bad\nerror")),
            ("disabledPlans", serde_json::json!([SKU, SKU])),
        ] {
            let mut raw = base.clone();
            raw["licenseAssignmentStates"][0][field] = value;
            invalid.push(raw);
        }
        for field in ["assignedLicenses", "licenseAssignmentStates"] {
            let mut raw = base.clone();
            let row = raw[field][0].clone();
            raw[field].as_array_mut().unwrap().push(row);
            invalid.push(raw);
        }
        for raw in invalid {
            assert_eq!(
                validate_user(raw.clone(), OBJECT).unwrap_err().code,
                "graph_read_invalid_response",
                "{raw}"
            );
        }
        let empty = serde_json::json!({"id": OBJECT, "accountEnabled": false, "assignedLicenses": [], "licenseAssignmentStates": []});
        assert!(!validate_user(empty, OBJECT).unwrap().account_enabled);
    }

    #[test]
    fn user_http_errors_and_redirects_fail_without_echoing_provider_content() {
        for status in [
            "202 Accepted",
            "302 Found",
            "401 Unauthorized",
            "403 Forbidden",
            "429 Too Many Requests",
            "500 Error",
        ] {
            let (origin, server) = server(vec![response(
                status,
                "Retry-After: 90\r\nLocation: https://evil.test\r\n",
                "private provider error",
            )]);
            let error = read_user_with_origin("private.token", OBJECT, &origin).unwrap_err();
            assert_eq!(server.join().unwrap().len(), 1);
            assert_eq!(error.code, format!("graph_read_http_{}", &status[..3]));
            assert_eq!(error.retry_after, (status.starts_with("429")).then_some(90));
            assert!(!error.code.contains("private"));
        }
    }

    #[test]
    fn user_malformed_oversized_or_non_json_success_is_rejected() {
        for (headers, body, expected) in [
            (
                "Content-Type: text/html\r\n",
                user().to_string(),
                "graph_read_unavailable",
            ),
            (
                "Content-Type: application/json\r\n",
                "{".into(),
                "graph_read_invalid_response",
            ),
            (
                "Content-Type: application/json\r\n",
                " ".repeat(MAX_BODY as usize + 1),
                "graph_read_unavailable",
            ),
        ] {
            let (origin, server) = server(vec![response("200 OK", headers, &body)]);
            assert_eq!(
                read_user_with_origin("private.token", OBJECT, &origin)
                    .unwrap_err()
                    .code,
                expected
            );
            server.join().unwrap();
        }
        for id in [
            "../users",
            "https://evil.test",
            "11111111111141118111111111111111",
        ] {
            assert_eq!(
                read_user_with_origin("token", id, "invalid-origin")
                    .unwrap_err()
                    .code,
                "graph_read_invalid_request"
            );
        }
    }
}
