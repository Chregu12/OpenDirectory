// Independent implementation of Google's published Licensing API; no SDK source copied.
use crate::http::{bearer, client, read_json, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use url::Url;

const STAGE: &str = "google_licenses";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    product_id: String,
    sku_id: String,
    user_id: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    customer_id: String,
    product_id: String,
    sku_id: String,
    assignments: Vec<Assignment>,
}

pub fn product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

fn inspect_with_origin(
    token: &str,
    customer: &str,
    product: &str,
    sku: &str,
    origin: &str,
) -> Result<Snapshot, Error> {
    if !bearer(token)
        || !customer.starts_with('C')
        || customer.len() < 2
        || customer.len() > 64
        || !customer.bytes().all(|c| c.is_ascii_alphanumeric())
        || !product_id(product)
        || !product_id(sku)
    {
        return Err(Error::new("google_licenses_invalid_request"));
    }
    let mut base = Url::parse(origin)
        .and_then(|url| {
            url.join(&format!(
                "/apps/licensing/v1/product/{product}/sku/{sku}/users"
            ))
        })
        .map_err(|_| Error::new("google_licenses_unavailable"))?;
    base.query_pairs_mut()
        .append_pair("customerId", customer)
        .append_pair("maxResults", "100");
    let client = client(STAGE, Default::default())?;
    let started = Instant::now();
    let mut next = base.clone();
    let mut seen_tokens = HashSet::new();
    let mut users = HashSet::new();
    let mut assignments = Vec::new();
    for _ in 0..16 {
        if started.elapsed() >= Duration::from_secs(15) {
            return Err(Error::new("google_licenses_incomplete"));
        }
        let raw = read_json(&client, &next, token, STAGE)?;
        let fail = || Error::new("google_licenses_invalid_response");
        let object = raw.as_object().ok_or_else(fail)?;
        if object.get("kind").and_then(|v| v.as_str()) != Some("licensing#licenseAssignmentList") {
            return Err(fail());
        }
        // Google omits an empty items array. Only an identified collection may do so.
        let items = match object.get("items") {
            None => Vec::new(),
            Some(value) => value.as_array().ok_or_else(fail)?.clone(),
        };
        if items.len() > 100 || assignments.len() + items.len() > 1000 {
            return Err(Error::new("google_licenses_incomplete"));
        }
        for item in items {
            let row: Assignment = serde_json::from_value(item).map_err(|_| fail())?;
            let parts = row.user_id.split('@').collect::<Vec<_>>();
            if row.product_id != product
                || row.sku_id != sku
                || row.user_id.len() > 254
                || parts.len() != 2
                || parts.iter().any(|part| part.is_empty())
                || row
                    .user_id
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                || !users.insert(row.user_id.to_lowercase())
            {
                return Err(fail());
            }
            assignments.push(row);
        }
        let page_token = object
            .get("nextPageToken")
            .map(|value| value.as_str().ok_or_else(fail))
            .transpose()?;
        match page_token {
            None | Some("") => {
                if started.elapsed() >= Duration::from_secs(15) {
                    return Err(Error::new("google_licenses_incomplete"));
                }
                assignments.sort_by_cached_key(|row| row.user_id.to_lowercase());
                return Ok(Snapshot {
                    customer_id: customer.into(),
                    product_id: product.into(),
                    sku_id: sku.into(),
                    assignments,
                });
            }
            Some(token) => {
                if token.len() > 2048 || token.chars().any(char::is_control) {
                    return Err(fail());
                }
                if !seen_tokens.insert(token.to_string()) {
                    return Err(Error::new("google_licenses_incomplete"));
                }
                // A page token is encoded as a value, never followed as a URL.
                next = base.clone();
                next.query_pairs_mut().append_pair("pageToken", token);
            }
        }
    }
    Err(Error::new("google_licenses_incomplete"))
}

pub fn inspect(token: &str, customer: &str, product: &str, sku: &str) -> Result<Snapshot, Error> {
    inspect_with_origin(
        token,
        customer,
        product,
        sku,
        "https://licensing.googleapis.com",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{response, server};
    use serde_json::json;
    fn assignment(user: &str) -> serde_json::Value {
        json!({"productId":"Google-Apps","skuId":"101","userId":user,"selfLink":"https://never-follow.test"})
    }
    fn page(items: serde_json::Value) -> serde_json::Value {
        json!({"kind":"licensing#licenseAssignmentList","items":items})
    }
    fn inspect_body(raw: serde_json::Value) -> Result<Snapshot, Error> {
        let (origin, server) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &raw.to_string(),
        )]);
        let result = inspect_with_origin("fixture.token", "C123", "Google-Apps", "101", &origin);
        server.join().unwrap();
        result
    }
    #[test]
    fn all_pages_are_bound_encoded_sorted_and_projected() {
        let token = "https://evil.test/?customerId=C999&key=x";
        let mut first = page(json!([assignment("z@example.test")]));
        first["nextPageToken"] = token.into();
        let second = page(json!([assignment("é@example.test")]));
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
        let result =
            inspect_with_origin("fixture.token", "C123", "Google-Apps", "101", &origin).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(result.assignments.len(), 2);
        for request in &requests {
            assert!(
                request.starts_with("GET /apps/licensing/v1/product/Google-Apps/sku/101/users?")
            );
            assert!(request
                .to_lowercase()
                .contains("authorization: bearer fixture.token"));
        }
        let url = Url::parse(&format!(
            "{origin}{}",
            requests[1].split_whitespace().nth(1).unwrap()
        ))
        .unwrap();
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "pageToken" && v == token));
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "customerId" && v == "C123"));
        assert!(!serde_json::to_string(&result).unwrap().contains("selfLink"));
    }
    #[test]
    fn empty_requires_an_identified_collection() {
        assert!(
            inspect_body(json!({"kind":"licensing#licenseAssignmentList"}))
                .unwrap()
                .assignments
                .is_empty()
        );
        assert!(inspect_body(page(json!([])))
            .unwrap()
            .assignments
            .is_empty());
        assert!(
            inspect_body(json!({"kind":"licensing#licenseAssignmentList","nextPageToken":""}))
                .unwrap()
                .assignments
                .is_empty()
        );
        for raw in [
            json!({}),
            page(json!(null)),
            json!({"kind":"wrong","items":[]}),
            json!({"kind":"licensing#licenseAssignmentList","nextPageToken":null}),
        ] {
            assert!(inspect_body(raw).is_err());
        }
    }
    #[test]
    fn wrong_sku_partial_duplicate_or_invalid_users_reject_whole_capture() {
        let mut wrong = assignment("a@example.test");
        wrong["skuId"] = "other".into();
        let mut missing = assignment("a@example.test");
        missing.as_object_mut().unwrap().remove("productId");
        for items in [
            json!([wrong]),
            json!([missing]),
            json!([assignment("invalid")]),
            json!([assignment("a@example.test"), assignment("A@example.test")]),
        ] {
            assert_eq!(
                inspect_body(page(items)).unwrap_err().code,
                "google_licenses_invalid_response"
            );
        }
    }
    #[test]
    fn cyclic_pages_fail_instead_of_returning_partial_data() {
        let raw =
            json!({"kind":"licensing#licenseAssignmentList","items":[],"nextPageToken":"again"})
                .to_string();
        let (origin, server) = server(vec![
            response("200 OK", "Content-Type: application/json\r\n", &raw),
            response("200 OK", "Content-Type: application/json\r\n", &raw),
        ]);
        assert_eq!(
            inspect_with_origin("fixture.token", "C123", "Google-Apps", "101", &origin)
                .unwrap_err()
                .code,
            "google_licenses_incomplete"
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }
    #[test]
    fn provider_errors_redirects_and_throttling_do_not_echo_secrets() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "429 Rate Limit",
            "302 Found",
            "500 Error",
        ] {
            let (origin, server) = server(vec![response(
                status,
                "Retry-After: 90\r\nLocation: https://evil.test\r\n",
                "private response",
            )]);
            let error = inspect_with_origin("fixture.token", "C123", "Google-Apps", "101", &origin)
                .unwrap_err();
            server.join().unwrap();
            assert_eq!(error.code, format!("google_licenses_http_{}", &status[..3]));
            assert_eq!(error.retry_after, status.starts_with("429").then_some(90));
        }
        assert_eq!(
            inspect_with_origin("token", "C123", "../escape", "101", "invalid")
                .unwrap_err()
                .code,
            "google_licenses_invalid_request"
        );
    }
}
