// Independent reader of Atlassian's current directory-user search API.
use crate::http::{bearer, client, request_json, Error};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const STAGE: &str = "atlassian_directory";
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    account_id: String,
    account_type: Option<String>,
    account_status: Option<String>,
    membership_status: Option<String>,
    status: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    organization_id: String,
    directory_id: String,
    users: Vec<User>,
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}
fn account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_|-:".contains(&c))
}
fn inspect_with_origin(
    token: &str,
    org: &str,
    directory: &str,
    origin: &str,
) -> Result<Snapshot, Error> {
    if !bearer(token) || !uuid(org) || !uuid(directory) {
        return Err(Error::new("atlassian_directory_invalid_request"));
    }
    let url = Url::parse(origin)
        .and_then(|url| {
            url.join(&format!(
                "/admin/v2/orgs/{org}/directories/{directory}/users/search"
            ))
        })
        .map_err(|_| Error::new("atlassian_directory_unavailable"))?;
    let client = client(STAGE, Default::default())?;
    let started = Instant::now();
    let mut users = Vec::new();
    let mut ids = HashSet::new();
    let mut cursors = HashSet::new();
    let mut cursor = None::<String>;
    for _ in 0..16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("atlassian_directory_incomplete"));
        }
        // The path alone does not restrict results to this directory in the v2 API.
        let mut body = json!({"limit":100,"directoryIds":[directory]});
        if let Some(value) = &cursor {
            body["cursor"] = value.clone().into();
        }
        let raw = request_json(
            client
                .post(url.clone())
                .bearer_auth(token)
                .header("Content-Type", "application/json")
                .body(body.to_string()),
            STAGE,
        )?;
        let fail = || Error::new("atlassian_directory_invalid_response");
        let object = raw.as_object().ok_or_else(fail)?;
        let rows = object
            .get("data")
            .and_then(|value| value.as_array())
            .ok_or_else(fail)?;
        if rows.len() > 100 || users.len() + rows.len() > 1000 {
            return Err(Error::new("atlassian_directory_incomplete"));
        }
        for row in rows {
            let user: User = serde_json::from_value(row.clone()).map_err(|_| fail())?;
            if !account_id(&user.account_id)
                || !ids.insert(user.account_id.clone())
                || user
                    .account_type
                    .as_ref()
                    .is_some_and(|value| value != "atlassian")
                || user.account_status.as_ref().is_some_and(|value| {
                    !["active", "inactive", "closed"].contains(&value.as_str())
                })
                || user.membership_status.as_ref().is_some_and(|value| {
                    !["active", "suspended", "no_membership"].contains(&value.as_str())
                })
                || user.status.as_ref().is_some_and(|value| {
                    ![
                        "active",
                        "suspended",
                        "not_invited",
                        "deactivated",
                        "for_deletion",
                    ]
                    .contains(&value.as_str())
                })
            {
                return Err(fail());
            }
            users.push(user);
        }
        let next = match object.get("links") {
            None => None,
            Some(links) => match links.as_object().ok_or_else(fail)?.get("next") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => Some(value.as_str().ok_or_else(fail)?),
            },
        };
        match next {
            None | Some("") => {
                if started.elapsed() >= Duration::from_secs(15) {
                    return Err(Error::new("atlassian_directory_incomplete"));
                }
                users.sort_by(|a, b| a.account_id.cmp(&b.account_id));
                return Ok(Snapshot {
                    organization_id: org.into(),
                    directory_id: directory.into(),
                    users,
                });
            }
            Some(value) => {
                if value.len() > 2048 || value.chars().any(char::is_control) {
                    return Err(fail());
                }
                if !cursors.insert(value.to_string()) {
                    return Err(Error::new("atlassian_directory_incomplete"));
                }
                cursor = Some(value.into());
            }
        }
    }
    Err(Error::new("atlassian_directory_incomplete"))
}
pub fn inspect(token: &str, org: &str, directory: &str) -> Result<Snapshot, Error> {
    inspect_with_origin(token, org, directory, "https://api.atlassian.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    const DIRECTORY: &str = "22222222-2222-4222-8222-222222222222";
    fn user(id: &str) -> serde_json::Value {
        json!({"accountId":id,"accountType":"atlassian","accountStatus":"active","membershipStatus":"active","status":"active","email":"private@example.test","picture":"https://evil.test"})
    }
    fn run(raw: serde_json::Value) -> Result<Snapshot, Error> {
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &raw.to_string(),
        )]);
        let result = inspect_with_origin("fixture.token", ORG, DIRECTORY, &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn every_search_pins_the_directory_and_cursor_is_data_not_a_url() {
        let cursor = "https://evil.test/?directoryIds=other";
        let first = json!({"data":[user("user-1")],"links":{"next":cursor}});
        let second = json!({"data":[{"accountId":"user-2"}],"links":{"next":null}});
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &first.to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &second.to_string(),
            ),
        ]);
        let result = inspect_with_origin("fixture.token", ORG, DIRECTORY, &origin).unwrap();
        let requests = server.join().unwrap();
        for (i, request) in requests.iter().enumerate() {
            assert!(request.starts_with(&format!(
                "POST /admin/v2/orgs/{ORG}/directories/{DIRECTORY}/users/search "
            )));
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["directoryIds"], json!([DIRECTORY]));
            assert_eq!(body["limit"], 100);
            if i == 1 {
                assert_eq!(body["cursor"], cursor);
            }
        }
        assert_eq!(result.users.len(), 2);
        assert!(result.users[1].status.is_none());
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("email"));
        assert!(!output.contains("picture"));
    }
    #[test]
    fn incomplete_ambiguous_or_invalid_accounts_are_not_a_successful_count() {
        for raw in [
            json!({}),
            json!({"data":null}),
            json!({"data":[user("duplicate"),user("duplicate")]}),
            json!({"data":[{"accountId":"user-1","accountStatus":"enabled"}]}),
            json!({"data":[],"links":{"next":{}}}),
        ] {
            assert!(run(raw).is_err());
        }
        assert!(run(json!({"data":[]})).unwrap().users.is_empty());
    }
    #[test]
    fn cyclic_cursors_do_not_return_partial_results() {
        let raw = json!({"data":[],"links":{"next":"again"}}).to_string();
        let (origin, server) = server(vec![
            response("200 OK", "Content-Type: application/json\r\n", &raw),
            response("200 OK", "Content-Type: application/json\r\n", &raw),
        ]);
        assert_eq!(
            inspect_with_origin("token", ORG, DIRECTORY, &origin)
                .unwrap_err()
                .code,
            "atlassian_directory_incomplete"
        );
        server.join().unwrap();
    }
    #[test]
    fn http_errors_redirects_and_throttling_remain_redacted() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "429 Too Many Requests",
            "302 Found",
        ] {
            let (origin, server) = server(vec![response(
                status,
                "Retry-After: 90\r\nLocation: https://evil.test\r\n",
                "private error",
            )]);
            let error = inspect_with_origin("token", ORG, DIRECTORY, &origin).unwrap_err();
            server.join().unwrap();
            assert_eq!(
                error.code,
                format!("atlassian_directory_http_{}", &status[..3])
            );
            assert_eq!(error.retry_after, status.starts_with("429").then_some(90));
        }
        assert_eq!(
            inspect_with_origin("token", ORG, "-", "invalid")
                .unwrap_err()
                .code,
            "atlassian_directory_invalid_request"
        );
    }
}
