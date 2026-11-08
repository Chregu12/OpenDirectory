mod adobe;
mod atlassian;
mod github;
mod gitlab;
mod google;
mod http;
mod microsoft;
mod slack;
#[cfg(test)]
mod test_http;

use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapacityRequest {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Operation {
    #[serde(rename = "microsoft.user", rename_all = "camelCase")]
    User {
        access_token: String,
        object_id: String,
    },
    #[serde(rename = "google.licenseAssignments", rename_all = "camelCase")]
    Google {
        access_token: String,
        customer_id: String,
        product_id: String,
        sku_id: String,
    },
    #[serde(rename = "github.copilotSeats", rename_all = "camelCase")]
    GitHub {
        access_token: String,
        organization: String,
    },
    #[serde(rename = "adobe.profileMembers", rename_all = "camelCase")]
    Adobe {
        access_token: String,
        client_id: String,
        organization_id: String,
        profile_id: String,
        profile_name: String,
    },
    #[serde(rename = "slack.users", rename_all = "camelCase")]
    Slack {
        access_token: String,
        directory_kind: String,
        directory_id: String,
    },
    #[serde(rename = "atlassian.directoryUsers", rename_all = "camelCase")]
    Atlassian {
        access_token: String,
        organization_id: String,
        directory_id: String,
    },
    #[serde(rename = "gitlab.billableMembers", rename_all = "camelCase")]
    GitLab {
        access_token: String,
        group_id: String,
        group_path: String,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Request {
    Capacity(CapacityRequest),
    Operation(Operation),
}

#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
    Capacity {
        ok: bool,
        rows: Vec<microsoft::Sku>,
    },
    User {
        ok: bool,
        user: microsoft::User,
    },
    Google {
        ok: bool,
        snapshot: google::Snapshot,
    },
    GitHub {
        ok: bool,
        snapshot: github::Snapshot,
    },
    Adobe {
        ok: bool,
        snapshot: adobe::Snapshot,
    },
    Slack {
        ok: bool,
        snapshot: slack::Snapshot,
    },
    Atlassian {
        ok: bool,
        snapshot: atlassian::Snapshot,
    },
    GitLab {
        ok: bool,
        snapshot: gitlab::Snapshot,
    },
    Error {
        ok: bool,
        code: String,
        #[serde(rename = "retryAfter", skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
    },
}

fn main() {
    let mut input = Vec::new();
    let result = (|| {
        io::stdin()
            .take(20_001)
            .read_to_end(&mut input)
            .map_err(|_| http::Error::new("graph_capacity_invalid_request"))?;
        if input.len() > 20_000 {
            return Err(http::Error::new("graph_capacity_invalid_request"));
        }
        let request: Request = serde_json::from_slice(&input)
            .map_err(|_| http::Error::new("graph_capacity_invalid_request"))?;
        match request {
            Request::Capacity(request) => microsoft::inspect(&request.access_token)
                .map(|rows| Reply::Capacity { ok: true, rows }),
            Request::Operation(Operation::User {
                access_token,
                object_id,
            }) => microsoft::read_user(&access_token, &object_id)
                .map(|user| Reply::User { ok: true, user }),
            Request::Operation(Operation::Google {
                access_token,
                customer_id,
                product_id,
                sku_id,
            }) => google::inspect(&access_token, &customer_id, &product_id, &sku_id)
                .map(|snapshot| Reply::Google { ok: true, snapshot }),
            Request::Operation(Operation::GitHub {
                access_token,
                organization,
            }) => github::inspect(&access_token, &organization)
                .map(|snapshot| Reply::GitHub { ok: true, snapshot }),
            Request::Operation(Operation::Adobe {
                access_token,
                client_id,
                organization_id,
                profile_id,
                profile_name,
            }) => adobe::inspect(
                &access_token,
                &client_id,
                &organization_id,
                &profile_id,
                &profile_name,
            )
            .map(|snapshot| Reply::Adobe { ok: true, snapshot }),
            Request::Operation(Operation::Slack {
                access_token,
                directory_kind,
                directory_id,
            }) => slack::inspect(&access_token, &directory_kind, &directory_id)
                .map(|snapshot| Reply::Slack { ok: true, snapshot }),
            Request::Operation(Operation::Atlassian {
                access_token,
                organization_id,
                directory_id,
            }) => atlassian::inspect(&access_token, &organization_id, &directory_id)
                .map(|snapshot| Reply::Atlassian { ok: true, snapshot }),
            Request::Operation(Operation::GitLab {
                access_token,
                group_id,
                group_path,
            }) => gitlab::inspect(&access_token, &group_id, &group_path)
                .map(|snapshot| Reply::GitLab { ok: true, snapshot }),
        }
    })();
    let reply = result.unwrap_or_else(|error| Reply::Error {
        ok: false,
        code: error.code,
        retry_after: error.retry_after,
    });
    if serde_json::to_writer(io::stdout().lock(), &reply).is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_keeps_legacy_capacity_and_requires_explicit_operations() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"accessToken":"fixture"}"#).unwrap(),
            Request::Capacity(_)
        ));
        for raw in [
            r#"{"operation":"microsoft.user","accessToken":"fixture","objectId":"11111111-1111-4111-8111-111111111111"}"#,
            r#"{"operation":"google.licenseAssignments","accessToken":"fixture","customerId":"C123","productId":"Google-Apps","skuId":"1010020027"}"#,
            r#"{"operation":"github.copilotSeats","accessToken":"fixture","organization":"fixture-org"}"#,
            r#"{"operation":"adobe.profileMembers","accessToken":"fixture","clientId":"fixture-client","organizationId":"A123@AdobeOrg","profileId":"42","profileName":"Creative Cloud"}"#,
            r#"{"operation":"slack.users","accessToken":"fixture","directoryKind":"workspace","directoryId":"T123"}"#,
            r#"{"operation":"atlassian.directoryUsers","accessToken":"fixture","organizationId":"11111111-1111-4111-8111-111111111111","directoryId":"22222222-2222-4222-8222-222222222222"}"#,
            r#"{"operation":"gitlab.billableMembers","accessToken":"fixture","groupId":"123","groupPath":"fixture-org"}"#,
        ] {
            assert!(matches!(
                serde_json::from_str::<Request>(raw).unwrap(),
                Request::Operation(_)
            ));
        }
        for raw in [
            r#"{"accessToken":"fixture","objectId":"user"}"#,
            r#"{"accessToken":"fixture","operation":"microsoft.assignLicense","objectId":"user"}"#,
            r#"{"accessToken":"fixture","operation":"github.copilotSeats","organization":"org","url":"https://evil.test"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(raw).is_err());
        }
    }
}
