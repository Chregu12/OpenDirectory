use crate::http::{bearer, client, request_json, Error};
use crate::microsoft::canonical_id;
use serde::Serialize;
use serde_json::json;
use url::Url;

#[derive(Debug, Serialize)]
pub struct AssignmentResponse {
    id: String,
}

fn failure(code: &str, uncertain: bool) -> Error {
    let mut error = Error::new(code);
    error.uncertain = Some(uncertain);
    error
}

fn assign_with_origin(
    token: &str,
    object_id: &str,
    sku_id: &str,
    disabled_plans: &[String],
    desired: bool,
    attempt_id: &str,
    origin: &str,
) -> Result<AssignmentResponse, Error> {
    if !bearer(token)
        || [object_id, sku_id, attempt_id]
            .iter()
            .any(|value| canonical_id(value).as_deref() != Some(*value))
        || disabled_plans.len() > 128
        || disabled_plans
            .iter()
            .any(|value| canonical_id(value).as_ref() != Some(value))
        || disabled_plans.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(failure("graph_write_invalid_request", false));
    }
    let url = Url::parse(origin)
        .and_then(|origin| origin.join(&format!("/v1.0/users/{object_id}/assignLicense")))
        .map_err(|_| failure("graph_write_invalid_request", false))?;
    let body = if desired {
        json!({"addLicenses":[{"skuId":sku_id,"disabledPlans":disabled_plans}],"removeLicenses":[]})
    } else {
        json!({"addLicenses":[],"removeLicenses":[sku_id]})
    };
    // The request ID correlates a dispatch; Graph does not promise deduplication.
    // Never retry here: the caller retains the durable intent and reviews unknown outcomes.
    let transport = client("graph_write", Default::default())
        .map_err(|_| failure("graph_write_unavailable", true))?;
    let data = request_json(
        transport
            .post(url)
            .bearer_auth(token)
            .header("client-request-id", attempt_id)
            .header("content-type", "application/json")
            .body(body.to_string()),
        "graph_write",
    )
    .map_err(|mut error| {
        error.uncertain = Some(!matches!(
            error.code.as_str(),
            "graph_write_http_400"
                | "graph_write_http_401"
                | "graph_write_http_403"
                | "graph_write_http_404"
                | "graph_write_http_405"
                | "graph_write_http_410"
                | "graph_write_http_412"
                | "graph_write_http_415"
                | "graph_write_http_422"
                | "graph_write_http_429"
        ));
        error
    })?;
    if data
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(object_id)
    {
        return Err(failure("graph_write_invalid_response", true));
    }
    // A matching response acknowledges the request. A separate read must confirm licensing.
    Ok(AssignmentResponse {
        id: object_id.into(),
    })
}

pub fn assign(
    token: &str,
    object_id: &str,
    sku_id: &str,
    disabled_plans: &[String],
    desired: bool,
    attempt_id: &str,
) -> Result<AssignmentResponse, Error> {
    assign_with_origin(
        token,
        object_id,
        sku_id,
        disabled_plans,
        desired,
        attempt_id,
        "https://graph.microsoft.com",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MAX_BODY;
    use crate::test_http::{response, server};

    const OBJECT: &str = "11111111-1111-4111-8111-111111111111";
    const SKU: &str = "22222222-2222-4222-8222-222222222222";
    const ATTEMPT: &str = "33333333-3333-4333-8333-333333333333";
    const PLAN: &str = "44444444-4444-4444-8444-444444444444";

    #[test]
    fn posts_exact_add_and_remove_requests_and_returns_only_the_bound_id() {
        for desired in [true, false] {
            let body = json!({"id": OBJECT.to_uppercase(), "displayName":"not forwarded"});
            let (origin, handle) = server(vec![response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &body.to_string(),
            )]);
            let plans = vec![PLAN.to_string()];
            let result = assign_with_origin(
                "private.token",
                OBJECT,
                SKU,
                &plans,
                desired,
                ATTEMPT,
                &origin,
            )
            .unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), json!({"id":OBJECT}));
            let requests = handle.join().unwrap();
            assert_eq!(requests.len(), 1);
            let (headers, payload) = requests[0].split_once("\r\n\r\n").unwrap();
            assert!(
                headers.starts_with(&format!("POST /v1.0/users/{OBJECT}/assignLicense HTTP/1.1"))
            );
            let headers = headers.to_ascii_lowercase();
            assert!(headers.contains("authorization: bearer private.token\r\n"));
            assert!(headers.contains(&format!("client-request-id: {ATTEMPT}")));
            let expected = if desired {
                json!({"addLicenses":[{"skuId":SKU,"disabledPlans":[PLAN]}],"removeLicenses":[]})
            } else {
                json!({"addLicenses":[],"removeLicenses":[SKU]})
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(payload).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn validates_targets_and_sorted_unique_plans_before_any_network_request() {
        for (token, object, sku, attempt, plans) in [
            ("", OBJECT, SKU, ATTEMPT, vec![]),
            ("token", "../other", SKU, ATTEMPT, vec![]),
            ("token", OBJECT, "invalid", ATTEMPT, vec![]),
            ("token", OBJECT, SKU, "invalid", vec![]),
            (
                "token",
                OBJECT,
                SKU,
                ATTEMPT,
                vec![PLAN.into(), PLAN.into()],
            ),
            ("token", OBJECT, SKU, ATTEMPT, vec![PLAN.into(), SKU.into()]),
            ("token", OBJECT, SKU, ATTEMPT, vec!["invalid".into()]),
            ("token", OBJECT, SKU, ATTEMPT, vec![PLAN.into(); 129]),
        ] {
            let error = assign_with_origin(token, object, sku, &plans, true, attempt, "not a URL")
                .unwrap_err();
            assert_eq!(error.code, "graph_write_invalid_request");
            assert_eq!(error.uncertain, Some(false));
        }
    }

    #[test]
    fn the_existing_maximum_token_and_plan_limits_fit_one_post() {
        let plans: Vec<_> = (0..128)
            .map(|i| format!("00000000-0000-4000-8000-{i:012x}"))
            .collect();
        let (origin, handle) = server(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &json!({"id":OBJECT}).to_string(),
        )]);
        assign_with_origin(
            &"t".repeat(16_384),
            OBJECT,
            SKU,
            &plans,
            true,
            ATTEMPT,
            &origin,
        )
        .unwrap();
        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 1);
        let (_, body) = requests[0].split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap()["addLicenses"][0]
                ["disabledPlans"],
            json!(plans)
        );
    }

    #[test]
    fn known_rejections_are_not_ambiguous_and_do_not_retry() {
        for status in [400, 401, 403, 404, 405, 410, 412, 415, 422, 429] {
            let headers = "Content-Type: application/json\r\nRetry-After: 9000\r\n";
            let (origin, handle) = server(vec![response(
                &format!("{status} Rejected"),
                headers,
                "private error body",
            )]);
            let error =
                assign_with_origin("private.token", OBJECT, SKU, &[], true, ATTEMPT, &origin)
                    .unwrap_err();
            assert_eq!(error.code, format!("graph_write_http_{status}"));
            assert_eq!(error.uncertain, Some(false));
            assert_eq!(
                error.retry_after,
                if status == 429 { Some(3600) } else { None }
            );
            assert!(!format!("{error:?}").contains("private"));
            assert_eq!(handle.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn unexpected_statuses_and_redirects_keep_the_write_outcome_unknown() {
        for status in [201, 202, 204, 302, 408, 409, 423, 500, 503] {
            let (origin, handle) = server(vec![response(
                &format!("{status} Unknown"),
                "Content-Type: application/json\r\nLocation: {ORIGIN}/other\r\n",
                "{}",
            )]);
            let error =
                assign_with_origin("private.token", OBJECT, SKU, &[], false, ATTEMPT, &origin)
                    .unwrap_err();
            assert_eq!(error.code, format!("graph_write_http_{status}"));
            assert_eq!(error.uncertain, Some(true));
            assert_eq!(handle.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn invalid_success_and_connection_loss_never_confirm_a_write() {
        for reply in [
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &json!({"id":SKU}).to_string(),
            ),
            response("200 OK", "Content-Type: application/json\r\n", "{"),
            response(
                "200 OK",
                "Content-Type: text/html\r\n",
                &json!({"id":OBJECT}).to_string(),
            ),
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                &" ".repeat(MAX_BODY as usize + 1),
            ),
            String::new(),
        ] {
            let (origin, handle) = server(vec![reply]);
            let error =
                assign_with_origin("private.token", OBJECT, SKU, &[], true, ATTEMPT, &origin)
                    .unwrap_err();
            assert_eq!(error.uncertain, Some(true));
            assert_eq!(handle.join().unwrap().len(), 1);
        }
    }
}
