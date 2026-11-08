// Independent UMAPI reader based on Adobe's published contract; no SDK source copied.
use crate::http::{bearer, client, email, read_json, text, Error};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;

const STAGE: &str = "adobe_profiles";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    #[serde(rename = "type")]
    kind: String,
    group_name: String,
    group_id: Option<u64>,
    product_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Groups {
    result: String,
    last_page: bool,
    groups: Vec<Group>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    id: Option<String>,
    email: String,
    #[serde(rename(deserialize = "type", serialize = "identityType"))]
    identity_type: Option<String>,
    status: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Users {
    result: String,
    last_page: bool,
    group_name: String,
    users: Vec<Member>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    organization_id: String,
    profile_id: String,
    profile_name: String,
    product_name: String,
    members: Vec<Member>,
}

fn valid_org(value: &str) -> bool {
    value.strip_suffix("@AdobeOrg").is_some_and(|prefix| {
        !prefix.is_empty() && prefix.len() <= 64 && prefix.bytes().all(|c| c.is_ascii_hexdigit())
    })
}
fn path(
    origin: &str,
    resource: &str,
    org: &str,
    page: usize,
    name: Option<&str>,
) -> Result<Url, Error> {
    let mut url = Url::parse(origin)
        .and_then(|url| url.join("/v2/usermanagement/"))
        .map_err(|_| Error::new("adobe_profiles_unavailable"))?;
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|_| Error::new("adobe_profiles_unavailable"))?;
        parts
            .pop_if_empty()
            .push(resource)
            .push(org)
            .push(&page.to_string());
        if let Some(name) = name {
            parts.push(name);
        }
    }
    Ok(url)
}
fn inspect_with_origin(
    token: &str,
    client_id: &str,
    org: &str,
    profile_id: &str,
    profile_name: &str,
    origin: &str,
) -> Result<Snapshot, Error> {
    let parsed_id = profile_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0 && id.to_string() == profile_id);
    if !bearer(token)
        || !valid_org(org)
        || parsed_id.is_none()
        || !text(profile_name, 255)
        || [".", ".."].contains(&profile_name)
        || !(16..=128).contains(&client_id.len())
        || !client_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(Error::new("adobe_profiles_invalid_request"));
    }
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        "x-api-key",
        HeaderValue::from_str(client_id)
            .map_err(|_| Error::new("adobe_profiles_invalid_request"))?,
    );
    let client = client(STAGE, headers)?;
    let started = Instant::now();
    let fail = || Error::new("adobe_profiles_invalid_response");
    let mut selected = None;
    let mut complete = false;
    let mut group_count = 0;
    let mut names = HashSet::new();
    // Groups are limited to five requests/minute by Adobe. Do not exceed that in a probe.
    for page in 0..5 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("adobe_profiles_incomplete"));
        }
        let raw: Groups = serde_json::from_value(read_json(
            &client,
            &path(origin, "groups", org, page, None)?,
            token,
            STAGE,
        )?)
        .map_err(|_| fail())?;
        if raw.result != "success" {
            return Err(fail());
        }
        group_count += raw.groups.len();
        if group_count > 1000 {
            return Err(Error::new("adobe_profiles_incomplete"));
        }
        for group in raw.groups {
            if !text(&group.group_name, 255) || !names.insert(group.group_name.clone()) {
                return Err(fail());
            }
            if group.group_name == profile_name {
                if group.kind != "PRODUCT_PROFILE" || group.group_id != parsed_id {
                    return Err(Error::new("adobe_profiles_binding_rejected"));
                }
                let product = group
                    .product_name
                    .filter(|value| text(value, 255))
                    .ok_or_else(fail)?;
                selected = Some(product);
            }
        }
        if raw.last_page {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(Error::new("adobe_profiles_incomplete"));
    }
    let product_name = selected.ok_or_else(|| Error::new("adobe_profiles_binding_rejected"))?;
    let mut members = Vec::new();
    let mut ids = HashSet::new();
    let mut identities = HashSet::new();
    for page in 0..16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("adobe_profiles_incomplete"));
        }
        let mut url = path(origin, "users", org, page, Some(profile_name))?;
        url.query_pairs_mut()
            .append_pair("directOnly", "false")
            .append_pair("excludeGroups", "true");
        let raw: Users =
            serde_json::from_value(read_json(&client, &url, token, STAGE)?).map_err(|_| fail())?;
        if raw.result != "success" || raw.group_name != profile_name {
            return Err(fail());
        }
        if members.len() + raw.users.len() > 1000 {
            return Err(Error::new("adobe_profiles_incomplete"));
        }
        for member in raw.users {
            if !email(&member.email)
                || member
                    .id
                    .as_ref()
                    .is_some_and(|id| !text(id, 128) || !ids.insert(id.clone()))
                || member.identity_type.as_ref().is_some_and(|kind| {
                    !["adobeID", "enterpriseID", "federatedID", "unknown"].contains(&kind.as_str())
                })
                || member.status.as_ref().is_some_and(|status| {
                    !["active", "disabled", "locked", "removed"].contains(&status.as_str())
                })
                || !identities.insert((member.email.to_lowercase(), member.identity_type.clone()))
            {
                return Err(fail());
            }
            members.push(member);
        }
        if raw.last_page {
            if started.elapsed() >= Duration::from_secs(15) {
                return Err(Error::new("adobe_profiles_incomplete"));
            }
            members.sort_by_cached_key(|member| {
                (member.email.to_lowercase(), member.identity_type.clone())
            });
            return Ok(Snapshot {
                organization_id: org.into(),
                profile_id: profile_id.into(),
                profile_name: profile_name.into(),
                product_name,
                members,
            });
        }
    }
    Err(Error::new("adobe_profiles_incomplete"))
}

pub fn inspect(
    token: &str,
    client_id: &str,
    org: &str,
    profile_id: &str,
    profile_name: &str,
) -> Result<Snapshot, Error> {
    inspect_with_origin(
        token,
        client_id,
        org,
        profile_id,
        profile_name,
        "https://usermanagement.adobe.io",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    use serde_json::json;
    const ORG: &str = "AB123@AdobeOrg";
    const CLIENT: &str = "fixture-client-123456";
    const NAME: &str = "Creative Cloud / Zürich";
    fn groups() -> serde_json::Value {
        json!({"result":"success","lastPage":true,"groups":[{"type":"PRODUCT_PROFILE","groupName":NAME,"groupId":42,"productName":"All Apps","licenseQuota":"not-a-purchased-quota"}]})
    }
    fn member() -> serde_json::Value {
        json!({"id":"adobe-user-1","email":"a@example.test","type":"federatedID","status":"active","firstname":"private"})
    }
    fn users(items: serde_json::Value) -> serde_json::Value {
        json!({"result":"success","lastPage":true,"groupName":NAME,"users":items})
    }
    fn run(
        raw_groups: serde_json::Value,
        raw_users: Option<serde_json::Value>,
    ) -> Result<Snapshot, Error> {
        let mut replies = vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &raw_groups.to_string(),
        )];
        if let Some(raw) = raw_users {
            replies.push(response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &raw.to_string(),
            ));
        }
        let (origin, server) = server(replies);
        let result = inspect_with_origin("fixture.token", CLIENT, ORG, "42", NAME, &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn validates_profile_identity_encodes_names_and_pages_members_without_pii_extras() {
        let mut first = users(json!([member()]));
        first["lastPage"] = false.into();
        let mut other = member();
        other["id"] = "other".into();
        other["email"] = "b@example.test".into();
        other.as_object_mut().unwrap().remove("status");
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &groups().to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &first.to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &users(json!([other])).to_string(),
            ),
        ]);
        let result =
            inspect_with_origin("fixture.token", CLIENT, ORG, "42", NAME, &origin).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /v2/usermanagement/groups/AB123@AdobeOrg/0 "));
        assert!(requests[1].contains("/users/AB123@AdobeOrg/0/Creative%20Cloud%20%2F%20Z%C3%BCrich?directOnly=false&excludeGroups=true"));
        assert!(requests[2].contains("/users/AB123@AdobeOrg/1/"));
        assert!(requests[0]
            .to_lowercase()
            .contains(&format!("x-api-key: {CLIENT}")));
        assert_eq!(result.members.len(), 2);
        assert!(result.members[1].status.is_none());
        assert_eq!(result.profile_id, "42");
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("firstname"));
        assert!(!output.contains("licenseQuota"));
        assert!(output.contains("identityType"));
    }
    #[test]
    fn wrong_type_id_missing_profile_or_ambiguous_metadata_cannot_be_a_license_profile() {
        for (key, value) in [
            ("type", json!("USER_GROUP")),
            ("groupId", json!(43)),
            ("groupName", json!("different")),
        ] {
            let mut raw = groups();
            raw["groups"][0][key] = value;
            assert!(run(raw, None).is_err());
        }
        let mut raw = groups();
        let duplicate = raw["groups"][0].clone();
        raw["groups"].as_array_mut().unwrap().push(duplicate);
        assert!(run(raw, None).is_err());
    }
    #[test]
    fn invalid_user_pages_and_duplicate_members_are_not_successful_empty_profiles() {
        for raw in [
            json!({"result":"success","groupName":NAME,"users":[]}),
            users(json!([member(), member()])),
            json!({"result":"error","lastPage":true,"groupName":NAME,"users":[]}),
            json!({"result":"success","lastPage":true,"groupName":"wrong","users":[]}),
        ] {
            assert!(run(groups(), Some(raw)).is_err());
        }
        let mut invalid = member();
        invalid["status"] = "provisioned".into();
        assert!(run(groups(), Some(users(json!([invalid])))).is_err());
        assert!(run(groups(), Some(users(json!([]))))
            .unwrap()
            .members
            .is_empty());
    }
    #[test]
    fn metadata_stops_at_five_pages_instead_of_exceeding_adobe_client_limit() {
        let replies = (0..5)
            .map(|_| {
                response(
                    "200 OK",
                    "Content-Type: application/json\r\n",
                    &json!({"result":"success","lastPage":false,"groups":[]}).to_string(),
                )
            })
            .collect();
        let (origin, server) = server(replies);
        assert_eq!(
            inspect_with_origin("token", CLIENT, ORG, "42", NAME, &origin)
                .unwrap_err()
                .code,
            "adobe_profiles_incomplete"
        );
        assert_eq!(server.join().unwrap().len(), 5);
    }
    #[test]
    fn provider_errors_redirects_and_retry_intervals_are_bounded() {
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
            let error = inspect_with_origin("token", CLIENT, ORG, "42", NAME, &origin).unwrap_err();
            server.join().unwrap();
            assert_eq!(error.code, format!("adobe_profiles_http_{}", &status[..3]));
            assert_eq!(error.retry_after, status.starts_with("429").then_some(90));
        }
        assert_eq!(
            inspect_with_origin("token", CLIENT, "../escape", "42", NAME, "invalid")
                .unwrap_err()
                .code,
            "adobe_profiles_invalid_request"
        );
    }
}
