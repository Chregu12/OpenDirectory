// Read Slack identity first: an Enterprise directory must never be labelled as one workspace.
use crate::http::{bearer, client, read_json, request_json, text, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;

const STAGE: &str = "slack_directory";
#[derive(Deserialize)]
struct Auth {
    ok: bool,
    team_id: Option<String>,
    enterprise_id: Option<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    user_name: String,
    active: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    schemas: Vec<String>,
    total_results: usize,
    start_index: usize,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<User>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    directory_kind: String,
    directory_id: String,
    users: Vec<User>,
}

fn slack_id(value: &str, prefixes: &[u8]) -> bool {
    (2..=64).contains(&value.len())
        && prefixes.contains(&value.as_bytes()[0])
        && value
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
fn inspect_with_origins(
    token: &str,
    kind: &str,
    id: &str,
    auth_origin: &str,
    scim_origin: &str,
) -> Result<Snapshot, Error> {
    if !bearer(token)
        || !(kind == "workspace" && slack_id(id, b"T")
            || kind == "enterprise" && slack_id(id, b"E"))
    {
        return Err(Error::new("slack_directory_invalid_request"));
    }
    let client = client(STAGE, Default::default())?;
    let started = Instant::now();
    let fail = || Error::new("slack_directory_invalid_response");
    let auth_url = Url::parse(auth_origin)
        .and_then(|url| url.join("/api/auth.test"))
        .map_err(|_| Error::new("slack_directory_unavailable"))?;
    let auth: Auth = serde_json::from_value(request_json(
        client
            .post(auth_url)
            .bearer_auth(token)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(""),
        STAGE,
    )?)
    .map_err(|_| fail())?;
    if !auth.ok {
        return Err(Error::new("slack_directory_auth_rejected"));
    }
    if kind == "workspace" && (auth.team_id.as_deref() != Some(id) || auth.enterprise_id.is_some())
        || kind == "enterprise" && auth.enterprise_id.as_deref() != Some(id)
    {
        return Err(Error::new("slack_directory_binding_rejected"));
    }
    let base = Url::parse(scim_origin)
        .and_then(|url| url.join("/scim/v2/Users"))
        .map_err(|_| Error::new("slack_directory_unavailable"))?;
    let mut users = Vec::new();
    let mut ids = HashSet::new();
    let mut total = None;
    for _ in 0..16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("slack_directory_incomplete"));
        }
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("startIndex", &(users.len() + 1).to_string())
            .append_pair("count", "100");
        let page: Page =
            serde_json::from_value(read_json(&client, &url, token, STAGE)?).map_err(|_| fail())?;
        if !page
            .schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:ListResponse")
            || page.start_index != users.len() + 1
            || page.items_per_page != page.resources.len()
            || page.items_per_page > 100
        {
            return Err(fail());
        }
        if page.total_results > 1000
            || total.is_some_and(|value| value != page.total_results)
            || users.len() + page.resources.len() > page.total_results
            || page.resources.is_empty() && users.len() != page.total_results
        {
            return Err(Error::new("slack_directory_incomplete"));
        }
        total = Some(page.total_results);
        for user in page.resources {
            if !slack_id(&user.id, b"UW")
                || !text(&user.user_name, 254)
                || !ids.insert(user.id.clone())
            {
                return Err(fail());
            }
            users.push(user);
        }
        if users.len() == page.total_results {
            if started.elapsed() >= Duration::from_secs(15) {
                return Err(Error::new("slack_directory_incomplete"));
            }
            users.sort_by(|a, b| a.id.cmp(&b.id));
            return Ok(Snapshot {
                directory_kind: kind.into(),
                directory_id: id.into(),
                users,
            });
        }
    }
    Err(Error::new("slack_directory_incomplete"))
}
pub fn inspect(token: &str, kind: &str, id: &str) -> Result<Snapshot, Error> {
    inspect_with_origins(
        token,
        kind,
        id,
        "https://slack.com",
        "https://api.slack.com",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    use serde_json::json;
    fn auth() -> serde_json::Value {
        json!({"ok":true,"team_id":"T123"})
    }
    fn user() -> serde_json::Value {
        json!({"id":"U123","userName":"alice","active":true,"emails":[{"value":"private@example.test"}],"meta":{"location":"https://evil.test"}})
    }
    fn page(start: usize, total: usize, rows: Vec<serde_json::Value>) -> serde_json::Value {
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"startIndex":start,"totalResults":total,"itemsPerPage":rows.len(),"Resources":rows})
    }
    fn run(
        auth: serde_json::Value,
        page: Option<serde_json::Value>,
        kind: &str,
        id: &str,
    ) -> Result<Snapshot, Error> {
        let mut replies = vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &auth.to_string(),
        )];
        if let Some(raw) = page {
            replies.push(response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &raw.to_string(),
            ));
        }
        let (origin, server) = server(replies);
        let result = inspect_with_origins("fixture.token", kind, id, &origin, &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn checks_identity_before_scim_paginates_and_projects_only_account_fields() {
        let mut second = user();
        second["id"] = "W456".into();
        second["active"] = false.into();
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &auth().to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &page(1, 2, vec![user()]).to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/scim+json; charset=utf-8\r\n",
                &page(2, 2, vec![second]).to_string(),
            ),
        ]);
        let result =
            inspect_with_origins("fixture.token", "workspace", "T123", &origin, &origin).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("POST /api/auth.test "));
        assert!(requests[1].starts_with("GET /scim/v2/Users?startIndex=1&count=100 "));
        assert!(requests[2].contains("startIndex=2&count=100"));
        assert_eq!(result.users.len(), 2);
        assert!(!result.users[1].active);
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("emails"));
        assert!(!output.contains("meta"));
    }
    #[test]
    fn enterprise_data_cannot_be_labelled_as_a_workspace_and_wrong_auth_stops_before_scim() {
        for raw in [
            json!({"ok":false,"error":"private"}),
            json!({"ok":true,"team_id":"T999"}),
            json!({"ok":true,"team_id":"T123","enterprise_id":"E123"}),
        ] {
            assert!(run(raw, None, "workspace", "T123").is_err());
        }
        assert!(run(
            json!({"ok":true,"team_id":"T123","enterprise_id":"E123"}),
            Some(page(1, 0, vec![])),
            "enterprise",
            "E123"
        )
        .unwrap()
        .users
        .is_empty());
        assert!(run(
            json!({"ok":true,"enterprise_id":"E999"}),
            None,
            "enterprise",
            "E123"
        )
        .is_err());
    }
    #[test]
    fn partial_wrong_schema_and_duplicate_accounts_never_become_valid_user_counts() {
        let mut missing = user();
        missing.as_object_mut().unwrap().remove("active");
        let mut wrong = page(1, 1, vec![user()]);
        wrong["schemas"] = json!(["error-schema"]);
        for raw in [
            page(2, 1, vec![user()]),
            page(1, 2, vec![user(), user()]),
            page(1, 1, vec![missing]),
            page(1, 1, vec![]),
            page(1, 1001, vec![]),
            wrong,
        ] {
            assert!(run(auth(), Some(raw), "workspace", "T123").is_err());
        }
    }
    #[test]
    fn changing_totals_and_stalled_pages_reject_the_entire_capture() {
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &auth().to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &page(1, 2, vec![user()]).to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &page(2, 3, vec![]).to_string(),
            ),
        ]);
        assert_eq!(
            inspect_with_origins("token", "workspace", "T123", &origin, &origin)
                .unwrap_err()
                .code,
            "slack_directory_incomplete"
        );
        server.join().unwrap();
    }
    #[test]
    fn auth_and_scim_http_errors_are_codes_without_provider_content() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "429 Too Many Requests",
            "302 Found",
        ] {
            let (origin, server) = server(vec![
                response(
                    "200 OK",
                    "Content-Type: application/json\r\n",
                    &auth().to_string(),
                ),
                response(
                    status,
                    "Retry-After: 90\r\nLocation: https://evil.test\r\n",
                    "private error",
                ),
            ]);
            let error =
                inspect_with_origins("token", "workspace", "T123", &origin, &origin).unwrap_err();
            server.join().unwrap();
            assert_eq!(error.code, format!("slack_directory_http_{}", &status[..3]));
            assert_eq!(error.retry_after, status.starts_with("429").then_some(90));
        }
        assert_eq!(
            inspect_with_origins("token", "workspace", "../escape", "invalid", "invalid")
                .unwrap_err()
                .code,
            "slack_directory_invalid_request"
        );
    }
}
