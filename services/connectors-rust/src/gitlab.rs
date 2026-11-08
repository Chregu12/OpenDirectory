// Independent GitLab.com billing-members reader. Provider links are validated before use.
use crate::http::{bearer, client, read_json, request_json_with_headers, text, Error};
use reqwest::header::{HeaderMap, LINK};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;

const STAGE: &str = "gitlab_billable";
#[derive(Deserialize)]
struct Group {
    id: u64,
    full_path: String,
    #[serde(deserialize_with = "required_parent")]
    parent_id: Option<u64>,
}
fn required_parent<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(de)
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Member {
    id: u64,
    username: String,
    state: Option<String>,
    membership_type: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    group_id: String,
    group_path: String,
    billable_members: Vec<Member>,
}

fn number(headers: &HeaderMap, key: &str) -> Result<Option<usize>, Error> {
    headers
        .get(key)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| Error::new("gitlab_billable_invalid_response"))
        })
        .transpose()
}
fn continuation(headers: &HeaderMap, base: &Url, page: usize) -> Result<Option<Url>, Error> {
    let fail = || Error::new("gitlab_billable_invalid_continuation");
    let mut next = None;
    for header in headers.get_all(LINK) {
        let raw = header.to_str().map_err(|_| fail())?;
        if raw.len() > 8192 {
            return Err(fail());
        }
        // Only the documented offset-link form is supported, not arbitrary Link parameters.
        for part in raw.split(',') {
            let (target, params) = part
                .trim()
                .strip_prefix('<')
                .and_then(|value| value.split_once('>'))
                .ok_or_else(fail)?;
            let is_next = params
                .split(';')
                .filter_map(|part| part.trim().split_once('='))
                .any(|(key, value)| {
                    key == "rel"
                        && value
                            .trim_matches('"')
                            .split_whitespace()
                            .any(|rel| rel == "next")
                });
            if !is_next {
                continue;
            }
            let url = Url::parse(target).map_err(|_| fail())?;
            if next.is_some()
                || url.origin() != base.origin()
                || url.path() != base.path()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(fail());
            }
            let mut keys = HashSet::new();
            let mut valid_page = false;
            let mut valid_size = false;
            for (key, value) in url.query_pairs() {
                if !keys.insert(key.to_string()) {
                    return Err(fail());
                }
                match key.as_ref() {
                    "page" if value == (page + 1).to_string() => valid_page = true,
                    "per_page" if value == "100" => valid_size = true,
                    _ => return Err(fail()),
                }
            }
            if !valid_page || !valid_size {
                return Err(fail());
            }
            next = Some(url);
        }
    }
    if let Some(value) = headers.get("x-next-page") {
        let expected = if next.is_some() {
            (page + 1).to_string()
        } else {
            String::new()
        };
        if value.to_str().ok() != Some(expected.as_str()) {
            return Err(fail());
        }
    }
    Ok(next)
}
fn inspect_with_origin(
    token: &str,
    group_id: &str,
    group_path: &str,
    origin: &str,
) -> Result<Snapshot, Error> {
    let id = group_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0 && *id <= 9_007_199_254_740_991 && id.to_string() == group_id);
    if !bearer(token)
        || id.is_none()
        || group_path.is_empty()
        || group_path.len() > 255
        || [".", ".."].contains(&group_path)
        || !group_path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err(Error::new("gitlab_billable_invalid_request"));
    }
    let mut group_url = Url::parse(origin)
        .and_then(|url| url.join(&format!("/api/v4/groups/{group_id}")))
        .map_err(|_| Error::new("gitlab_billable_unavailable"))?;
    group_url
        .query_pairs_mut()
        .append_pair("with_projects", "false");
    let client = client(STAGE, Default::default())?;
    let started = Instant::now();
    let fail = || Error::new("gitlab_billable_invalid_response");
    let group: Group = serde_json::from_value(read_json(&client, &group_url, token, STAGE)?)
        .map_err(|_| fail())?;
    if Some(group.id) != id || group.full_path != group_path || group.parent_id.is_some() {
        return Err(Error::new("gitlab_billable_binding_rejected"));
    }
    let base = group_url
        .join(&format!("/api/v4/groups/{group_id}/billable_members"))
        .map_err(|_| fail())?;
    let mut next = base.clone();
    next.query_pairs_mut()
        .append_pair("page", "1")
        .append_pair("per_page", "100");
    let mut members = Vec::new();
    let mut ids = HashSet::new();
    let mut total = None;
    for page in 1..=16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("gitlab_billable_incomplete"));
        }
        let (raw, headers) =
            request_json_with_headers(client.get(next.clone()).bearer_auth(token), STAGE)?;
        let rows: Vec<Member> = serde_json::from_value(raw).map_err(|_| fail())?;
        if number(&headers, "x-page")?.is_some_and(|value| value != page)
            || number(&headers, "x-per-page")?.is_some_and(|value| value != 100)
        {
            return Err(fail());
        }
        if let Some(value) = number(&headers, "x-total")? {
            if value > 1000 || total.is_some_and(|total| total != value) {
                return Err(Error::new("gitlab_billable_incomplete"));
            }
            total = Some(value);
        }
        if rows.len() > 100 || members.len() + rows.len() > 1000 {
            return Err(Error::new("gitlab_billable_incomplete"));
        }
        let page_size = rows.len();
        for member in rows {
            if member.id == 0
                || member.id > 9_007_199_254_740_991
                || !ids.insert(member.id)
                || !text(&member.username, 255)
                || member.state.as_ref().is_some_and(|value| !text(value, 64))
                || member
                    .membership_type
                    .as_ref()
                    .is_some_and(|value| !text(value, 64))
            {
                return Err(fail());
            }
            members.push(member);
        }
        let follow = continuation(&headers, &base, page)?;
        if follow.is_some() && page_size == 0 || total.is_some_and(|value| members.len() > value) {
            return Err(Error::new("gitlab_billable_incomplete"));
        }
        match follow {
            Some(url) => next = url,
            None => {
                if total.is_some_and(|value| value != members.len())
                    || total.is_none() && page_size == 100
                    || started.elapsed() >= Duration::from_secs(15)
                {
                    return Err(Error::new("gitlab_billable_incomplete"));
                }
                members.sort_by_key(|member| member.id);
                return Ok(Snapshot {
                    group_id: group_id.into(),
                    group_path: group_path.into(),
                    billable_members: members,
                });
            }
        }
    }
    Err(Error::new("gitlab_billable_incomplete"))
}
pub fn inspect(token: &str, group_id: &str, group_path: &str) -> Result<Snapshot, Error> {
    inspect_with_origin(token, group_id, group_path, "https://gitlab.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    use serde_json::json;
    fn group() -> serde_json::Value {
        json!({"id":123,"full_path":"fixture-org","parent_id":null})
    }
    fn member(id: u64) -> serde_json::Value {
        json!({"id":id,"username":format!("member-{id}"),"state":"active","membership_type":"group_member","email":"private@example.test","avatar_url":"https://evil.test"})
    }
    fn run(
        group: serde_json::Value,
        members: Option<(String, serde_json::Value)>,
    ) -> Result<Snapshot, Error> {
        let mut replies = vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &group.to_string(),
        )];
        if let Some((headers, raw)) = members {
            replies.push(response(
                "200 OK",
                &format!("Content-Type: application/json\r\n{headers}"),
                &raw.to_string(),
            ));
        }
        let (origin, server) = server(replies);
        let result = inspect_with_origin("fixture.token", "123", "fixture-org", &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn validates_top_level_identity_then_follows_only_the_bound_page_link() {
        let headers="Content-Type: application/json\r\nX-Page: 1\r\nX-Per-Page: 100\r\nX-Total: 2\r\nX-Next-Page: 2\r\nLink: <{ORIGIN}/api/v4/groups/123/billable_members?page=2&per_page=100>; rel=\"next\"\r\n";
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &group().to_string(),
            ),
            response("200 OK", headers, &json!([member(1)]).to_string()),
            response(
                "200 OK",
                "Content-Type: application/json\r\nX-Page: 2\r\nX-Total: 2\r\nX-Next-Page: \r\n",
                &json!([member(2)]).to_string(),
            ),
        ]);
        let result = inspect_with_origin("fixture.token", "123", "fixture-org", &origin).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /api/v4/groups/123?with_projects=false "));
        assert!(
            requests[2].starts_with("GET /api/v4/groups/123/billable_members?page=2&per_page=100 ")
        );
        assert_eq!(result.billable_members.len(), 2);
        assert!(!serde_json::to_string(&result).unwrap().contains("email"));
    }
    #[test]
    fn wrong_id_path_parent_or_missing_parent_cannot_alias_another_billing_group() {
        for (key, value) in [
            ("id", json!(124)),
            ("full_path", json!("other")),
            ("parent_id", json!(1)),
        ] {
            let mut raw = group();
            raw[key] = value;
            assert!(run(raw, None).is_err());
        }
        let mut missing = group();
        missing.as_object_mut().unwrap().remove("parent_id");
        assert!(run(missing, None).is_err());
    }
    #[test]
    fn untrusted_skip_duplicate_and_parameter_changing_links_are_rejected() {
        let base = Url::parse("https://gitlab.com/api/v4/groups/123/billable_members").unwrap();
        for target in [
            "https://evil.test/api/v4/groups/123/billable_members?page=2&per_page=100",
            "https://gitlab.com/api/v4/groups/124/billable_members?page=2&per_page=100",
            "https://gitlab.com/api/v4/groups/123/billable_members?page=3&per_page=100",
            "https://gitlab.com/api/v4/groups/123/billable_members?page=2&page=2&per_page=100",
            "https://gitlab.com/api/v4/groups/123/billable_members?page=2&per_page=100&sudo=1",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(LINK, format!("<{target}>; rel=\"next\"").parse().unwrap());
            assert!(continuation(&headers, &base, 1).is_err());
        }
    }
    #[test]
    fn incomplete_totals_missing_pages_and_duplicate_members_do_not_become_counts() {
        for (headers, raw) in [
            ("X-Total: 2\r\n", json!([member(1)])),
            ("X-Page: 2\r\n", json!([member(1)])),
            ("", json!([member(1), member(1)])),
            ("", json!({})),
            ("X-Total: 0\r\n", json!([member(1)])),
        ] {
            assert!(run(group(), Some((headers.into(), raw))).is_err());
        }
        assert!(run(group(), Some(("".into(), json!([]))))
            .unwrap()
            .billable_members
            .is_empty());
    }
    #[test]
    fn changing_totals_after_a_valid_first_page_reject_the_whole_capture() {
        let (origin,server)=server(vec![response("200 OK","Content-Type: application/json\r\n",&group().to_string()),response("200 OK","Content-Type: application/json\r\nX-Total: 2\r\nLink: <{ORIGIN}/api/v4/groups/123/billable_members?page=2&per_page=100>; rel=\"next\"\r\n",&json!([member(1)]).to_string()),response("200 OK","Content-Type: application/json\r\nX-Total: 3\r\n",&json!([member(2)]).to_string())]);
        assert_eq!(
            inspect_with_origin("token", "123", "fixture-org", &origin)
                .unwrap_err()
                .code,
            "gitlab_billable_incomplete"
        );
        server.join().unwrap();
    }
    #[test]
    fn billing_errors_never_fall_back_to_public_group_members() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "429 Too Many Requests",
            "302 Found",
        ] {
            let (origin, server) = server(vec![
                response(
                    "200 OK",
                    "Content-Type: application/json\r\n",
                    &group().to_string(),
                ),
                response(
                    status,
                    "Retry-After: 90\r\nLocation: https://evil.test\r\n",
                    "private error",
                ),
            ]);
            let error = inspect_with_origin("token", "123", "fixture-org", &origin).unwrap_err();
            assert_eq!(server.join().unwrap().len(), 2);
            assert_eq!(error.code, format!("gitlab_billable_http_{}", &status[..3]));
            assert_eq!(error.retry_after, status.starts_with("429").then_some(90));
        }
    }
}
