// Independent implementation of GitHub's published Copilot seat API.
use crate::http::{bearer, client, read_json, Error};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;

const STAGE: &str = "github_copilot";
#[derive(Debug, Deserialize)]
struct Assignee {
    id: u64,
    login: String,
}
#[derive(Debug, Deserialize)]
struct Team {
    id: u64,
}
#[derive(Debug, Deserialize)]
struct RawSeat {
    assignee: Assignee,
    assigning_team: Option<Team>,
    #[serde(deserialize_with = "required_nullable")]
    pending_cancellation_date: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Page {
    total_seats: usize,
    seats: Vec<RawSeat>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Seat {
    assignee_id: u64,
    login: String,
    assigning_team_id: Option<u64>,
    pending_cancellation_date: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    organization: String,
    total_seats: usize,
    seats: Vec<Seat>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(de)
}
pub fn login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
fn user_login(value: &str) -> bool {
    if login(value) {
        return true;
    }
    value.len() <= 39
        && value.split_once('_').is_some_and(|(name, suffix)| {
            login(name)
                && (3..=8).contains(&suffix.len())
                && suffix.bytes().all(|c| c.is_ascii_alphanumeric())
        })
}
fn valid_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let year = value[..4].parse::<u32>().unwrap();
    let month = value[5..7].parse::<usize>().unwrap();
    let day = value[8..].parse::<u32>().unwrap();
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year > 0 && (1..=12).contains(&month) && day > 0 && day <= days[month - 1]
}

fn inspect_with_origin(token: &str, organization: &str, origin: &str) -> Result<Snapshot, Error> {
    if !bearer(token) || !login(organization) {
        return Err(Error::new("github_copilot_invalid_request"));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("OpenDirectory-License-Connector"),
    );
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2026-03-10"),
    );
    let client = client(STAGE, headers)?;
    let started = Instant::now();
    let base = Url::parse(origin)
        .and_then(|url| url.join(&format!("/orgs/{organization}/copilot/billing/seats")))
        .map_err(|_| Error::new("github_copilot_unavailable"))?;
    let mut total = None;
    let mut seats = Vec::new();
    let mut ids = HashSet::new();
    let mut logins = HashSet::new();
    for page_number in 1..=16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("github_copilot_incomplete"));
        }
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page_number.to_string());
        let raw = read_json(&client, &url, token, STAGE)?;
        let fail = || Error::new("github_copilot_invalid_response");
        let page: Page = serde_json::from_value(raw).map_err(|_| fail())?;
        if page.total_seats > 1000 || total.is_some_and(|count| count != page.total_seats) {
            return Err(Error::new("github_copilot_incomplete"));
        }
        total = Some(page.total_seats);
        if page.seats.len() != 100.min(page.total_seats.saturating_sub(seats.len())) {
            return Err(Error::new("github_copilot_incomplete"));
        }
        for row in page.seats {
            let team_id = row.assigning_team.map(|team| team.id);
            if row.assignee.id == 0
                || row.assignee.id > 9_007_199_254_740_991
                || !user_login(&row.assignee.login)
                || !ids.insert(row.assignee.id)
                || !logins.insert(row.assignee.login.to_ascii_lowercase())
                || team_id.is_some_and(|id| id == 0 || id > 9_007_199_254_740_991)
                || row
                    .pending_cancellation_date
                    .as_ref()
                    .is_some_and(|date| !valid_date(date))
            {
                return Err(fail());
            }
            seats.push(Seat {
                assignee_id: row.assignee.id,
                login: row.assignee.login,
                assigning_team_id: team_id,
                pending_cancellation_date: row.pending_cancellation_date,
            });
        }
        if seats.len() == page.total_seats {
            if started.elapsed() >= Duration::from_secs(15) {
                return Err(Error::new("github_copilot_incomplete"));
            }
            seats.sort_by_key(|seat| seat.assignee_id);
            return Ok(Snapshot {
                organization: organization.to_ascii_lowercase(),
                total_seats: page.total_seats,
                seats,
            });
        }
    }
    Err(Error::new("github_copilot_incomplete"))
}

pub fn inspect(token: &str, organization: &str) -> Result<Snapshot, Error> {
    inspect_with_origin(token, organization, "https://api.github.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    use serde_json::json;
    fn seat(id: u64) -> serde_json::Value {
        json!({"assignee":{"id":id,"login":format!("member-{id}"),"avatar_url":"private"},"pending_cancellation_date":null,"last_activity_at":"private"})
    }
    fn inspect_body(raw: serde_json::Value) -> Result<Snapshot, Error> {
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &raw.to_string(),
        )]);
        let result = inspect_with_origin("fixture.token", "fixture-org", &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn fixed_pagination_checks_totals_and_projects_only_seat_fields() {
        let mut first: Vec<_> = (1..=100).map(seat).collect();
        first[0]["assignee"]["login"] = "mona-cat_octo".into();
        first[0]["assigning_team"] = json!({"id":42,"description":"private"});
        let mut last = seat(101);
        last["pending_cancellation_date"] = "2028-02-29".into();
        let a = json!({"total_seats":101,"seats":first});
        let b = json!({"total_seats":101,"seats":[last]});
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\nLink: <https://evil.test>; rel=\"next\"\r\n",
                &a.to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &b.to_string(),
            ),
        ]);
        let result = inspect_with_origin("fixture.token", "Fixture-Org", &origin).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1]
            .starts_with("GET /orgs/Fixture-Org/copilot/billing/seats?per_page=100&page=2"));
        assert!(requests[0]
            .to_lowercase()
            .contains("x-github-api-version: 2026-03-10"));
        assert!(requests[0]
            .to_lowercase()
            .contains("user-agent: opendirectory-license-connector"));
        assert_eq!(result.organization, "fixture-org");
        assert_eq!(result.seats[0].assigning_team_id, Some(42));
        assert_eq!(result.seats.len(), 101);
        assert!(!serde_json::to_string(&result).unwrap().contains("private"));
    }
    #[test]
    fn invalid_missing_and_duplicate_seats_are_not_an_inventory() {
        let mut missing = seat(1);
        missing
            .as_object_mut()
            .unwrap()
            .remove("pending_cancellation_date");
        let mut wrong_date = seat(1);
        wrong_date["pending_cancellation_date"] = "2026-02-29".into();
        for raw in [
            json!({}),
            json!({"total_seats":1,"seats":[]}),
            json!({"total_seats":2,"seats":[seat(1),seat(1)]}),
            json!({"total_seats":1,"seats":[missing]}),
            json!({"total_seats":1,"seats":[wrong_date]}),
            json!({"total_seats":1001,"seats":[]}),
        ] {
            assert!(inspect_body(raw).is_err());
        }
        assert!(inspect_body(json!({"total_seats":0,"seats":[]}))
            .unwrap()
            .seats
            .is_empty());
    }
    #[test]
    fn changing_totals_never_return_a_partial_success() {
        let a = json!({"total_seats":101,"seats":(1..=100).map(seat).collect::<Vec<_>>()});
        let b = json!({"total_seats":100,"seats":[]});
        let (origin, server) = server(vec![
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &a.to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &b.to_string(),
            ),
        ]);
        assert_eq!(
            inspect_with_origin("fixture.token", "fixture-org", &origin)
                .unwrap_err()
                .code,
            "github_copilot_incomplete"
        );
        server.join().unwrap();
    }
    #[test]
    fn forbidden_rate_limit_has_backoff_but_ordinary_forbidden_does_not() {
        for (status, headers, retry) in [
            ("403 Forbidden", "", None),
            ("403 Forbidden", "Retry-After: 90\r\n", Some(90)),
            (
                "403 Forbidden",
                "X-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 9999999999\r\n",
                Some(3600),
            ),
            ("429 Rate Limit", "Retry-After: 90\r\n", Some(90)),
            ("302 Found", "Location: https://evil.test\r\n", None),
        ] {
            let (origin, server) = server(vec![response(status, headers, "private error")]);
            let error = inspect_with_origin("fixture.token", "fixture-org", &origin).unwrap_err();
            server.join().unwrap();
            assert_eq!(error.retry_after, retry);
            assert!(!error.code.contains("private"));
        }
        assert_eq!(
            inspect_with_origin("token", "../escape", "invalid")
                .unwrap_err()
                .code,
            "github_copilot_invalid_request"
        );
    }
}
