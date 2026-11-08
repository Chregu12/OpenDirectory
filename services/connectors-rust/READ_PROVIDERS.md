# Provider readers: read-only connection tests

These implementations are independent Rust HTTP clients based on the published
[Google Licensing API](https://developers.google.com/workspace/admin/licensing/reference/rest/v1/licenseAssignments/listForProductAndSku)
and [GitHub Copilot seat API](https://docs.github.com/en/rest/copilot/copilot-user-management?apiVersion=2026-03-10#list-all-copilot-seat-assignments-for-an-organization).
The earlier SDK research is recorded in
[the architecture evaluation](../../docs/architecture/rust-connector-evaluation.md).
No SDK source was copied and no SDK dependency was added.

The executable is included in policy-service `1.0.26`. The manual probe is a
connection test, not a scheduled sync. It does not write the database, change
catalog entries, provision accounts, assign licenses or infer local user links.
The existing provider registry/fulfillment worker is still Microsoft-specific;
these new readers do not create entries in that registry or adopt company pools.
The normal `/licenses` view is unchanged by this step.

## Google Workspace

1. Enable the Enterprise License Manager API in the Google Cloud project.
2. Create a service account and configure Workspace domain-wide delegation for
   its numeric OAuth client ID. An authorized Workspace administrator must grant
   exactly `https://www.googleapis.com/auth/apps.licensing` for this read path.
   Google does not offer a separate read-only scope for this endpoint: the scope
   can also authorize writes, while our executable implements GET only. Review
   that distinction before creating the protected configuration.
3. Choose a delegated Workspace administrator with license-reading privileges,
   the actual Admin Console customer ID (`C...`) and explicit
   [product/SKU IDs](https://developers.google.com/workspace/admin/licensing/v1/how-tos/products).
   `my_customer`, domains, email guesses and arbitrary URLs are not accepted as
   customer identifiers.
4. Create the following JSON outside the repository or in the credential store.
   Replace every placeholder with the reviewed connection's values; the private
   key is the service account's RSA PEM key. OAuth flow follows Google's
   [service account specification](https://developers.google.com/identity/protocols/oauth2/service-account).

```json
{
  "schemaVersion": 1,
  "provider": "google-workspace",
  "consentReviewed": true,
  "customerId": "C01234567",
  "productId": "Google-Apps",
  "skuId": "1010020027",
  "serviceAccountEmail": "connector@YOUR-PROJECT.iam.gserviceaccount.com",
  "delegatedSubject": "license-admin@YOUR-DOMAIN.example",
  "privateKey": "-----BEGIN PRIVATE KEY-----\nREPLACE-WITH-REAL-KEY\n-----END PRIVATE KEY-----\n"
}
```

Google is queried only at
`https://licensing.googleapis.com/apps/licensing/v1/product/{productId}/sku/{skuId}/users`.
The requested customer/product/SKU remains fixed across pages. Each returned row
must match that product/SKU. `userId` is Google's current primary email, not an
immutable user ID; no OpenDirectory identity match is inferred from it.

## GitHub Copilot

1. Use a GitHub.com organization with Copilot Business or Enterprise and an
   authorized organization owner. Prepare an approved fine-grained PAT with
   **GitHub Copilot Business: read** organization permission, or an appropriate
   GitHub App token with that permission. The endpoint also supports the broader
   Administration read permission; this probe does not need it.
2. Pin the exact organization and token in a protected JSON file:

```json
{
  "schemaVersion": 1,
  "provider": "github-copilot",
  "consentReviewed": true,
  "organization": "YOUR-ORGANIZATION",
  "accessToken": "REPLACE-WITH-APPROVED-TOKEN"
}
```

The token must actually be accepted for the selected organization's seat API;
merely obtaining a token does not prove that permission. App-token renewal and
PAT rotation are external to this manual probe. Only `api.github.com` is used;
GitHub Enterprise Server and GHE.com data-residency hosts are not supported yet.
The API is documented as public preview; requests pin version `2026-03-10`.

The client calls only `/orgs/{organization}/copilot/billing/seats`. It retains
numeric assignee IDs, current logins, optional assigning-team IDs and pending
cancellation dates. A missing team ID is not proof of an exclusively owned direct
assignment. Enterprise managed usernames with underscore/shortcode are supported.
Pending cancellation does not make a billed seat a free commercial quota.

## Adobe Enterprise / Education

An Adobe System Administrator creates a User Management API integration with
OAuth Server-to-Server credentials in the Adobe Developer Console. Pin the
organization ID and one actual product profile's numeric ID and exact name from
the Admin Console/UMAPI group listing. Ordinary user groups and administrative
groups are rejected for this reader.

```json
{
  "schemaVersion": 1,
  "provider": "adobe-enterprise",
  "consentReviewed": true,
  "organizationId": "REPLACE-WITH-HEX-ORG-ID@AdobeOrg",
  "profileId": "123456",
  "profileName": "REPLACE-WITH-EXACT-PRODUCT-PROFILE",
  "clientId": "REPLACE-WITH-CLIENT-ID",
  "clientSecret": "REPLACE-WITH-CLIENT-SECRET"
}
```

The examples are placeholders, not usable credentials. The profile ID is a
canonical positive decimal string, avoiding loss of precision for Adobe long
IDs. The organization prefix must be hexadecimal. The client ID is also sent as
`x-api-key`, and the secret stays in the Node token client.

The token client uses the current
[OAuth Server-to-Server token reference](https://developer.adobe.com/developer-console/docs/guides/authentication/ServerToServerAuthentication/ims)
endpoint `https://ims-na1.adobelogin.com/ims/token/v3` with body parameters and
fixed scope `openid,AdobeID,user_management_sdk`. The older UMAPI authentication
page still demonstrates v2; the published current general S2S reference specifies
v3. There is no JWT-credential exchange or automatic fallback to another token
endpoint. Token expiration is interpreted in seconds.

UMAPI credentials are administrative and can authorize writes beyond this reader;
there is no claim of a separately read-only credential. Our implementation only
uses GET on the UMAPI host. It first pages
[groups and profiles](https://adobe-apiplatform.github.io/umapi-documentation/en/api/group.html)
and confirms the selected type `PRODUCT_PROFILE`, ID and name, then reads its
[members](https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersByGroup.html).
Group names are encoded as path segments, including slashes and non-ASCII text.
`directOnly=false` includes inherited membership; `excludeGroups=true` avoids
retrieving unrelated group memberships. No exclusive direct ownership is inferred.

Metadata reads stop after five pages, respecting the documented per-client
five-calls/minute limit for that endpoint within a single probe. Other clients
or repeated manual probes can still exhaust that limit: honor returned 429
Retry-After and do not run a tight retry loop. Missing profiles, wrong IDs, wrong
types, error results inside HTTP 200 and missing `lastPage` reject the capture.
404 is an error, not an empty profile.

The normalized snapshot retains only member ID (when present), email, identity
type and account status (both nullable when not supplied). Missing values do not
become active/provisioned state. The CLI emits profile binding and observed member
count without individual identities. Membership and account status do not prove
successful product provisioning. `licenseQuota` can represent resources allocated
to a profile, and is deliberately not imported as purchased capacity.

## Slack SCIM

Slack SCIM is available on Business+ and Enterprise plans. An authorized owner or
administrator must install/configure an app with the documented broad **admin**
OAuth scope. On Enterprise, an Org Owner must install the SCIM app. This scope
also enables writes; the new connector does not implement them. Its only POST is
the non-mutating `auth.test` identity check; account data is fetched with GET.

```json
{
  "schemaVersion": 1,
  "provider": "slack-scim",
  "consentReviewed": true,
  "directoryKind": "workspace",
  "directoryId": "T12345678",
  "accessToken": "REPLACE-WITH-APPROVED-SCIM-TOKEN"
}
```

For an Enterprise organization, use `directoryKind: "enterprise"` and its `E...`
ID instead. The connector verifies the selected ID against the token's
[auth.test identity](https://docs.slack.dev/reference/methods/auth.test/) before
any SCIM request. A workspace configuration rejects an auth response that carries
an Enterprise ID: Enterprise SCIM directory data must not be represented as only
one constituent workspace. An Enterprise configuration must explicitly match the
returned Enterprise ID and observes the whole organization.

The reader accepts JSON and the standard SCIM JSON media type, then calls only
`https://api.slack.com/scim/v2/Users` using
[SCIM 2.0 pagination](https://docs.slack.dev/reference/scim-api/). It requires the
ListResponse schema, exact start index, matching resource/page counts, stable
totals and unique user IDs. It keeps only ID, username and explicit active flag;
profile emails, addresses, manager data and resource URLs are dropped. Missing
active flags are rejected, rather than defaulting to active or inactive.

The CLI returns observed user count and active-account count for the selected
directory. Those are not paid seat counts: guest billing and commercial capacity
are separate contracts. Tokens, renewal and rotation are supplied externally;
this probe does not implement an OAuth installation UI. Public Slack hosts are
fixed; GovSlack is not supported. See
[Slack SCIM setup and permission requirements](https://docs.slack.dev/admins/scim-api/).

## Atlassian Cloud organization directory

Use an organization-administrator API key that is approved for the current
[Search for users endpoint](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-users/#api-v2-orgs-orgid-directories-directoryid-users-search-post).
Pin the actual organization ID and one directory ID as canonical lowercase UUIDs:

```json
{
  "schemaVersion": 1,
  "provider": "atlassian-cloud",
  "consentReviewed": true,
  "organizationId": "11111111-1111-4111-8111-111111111111",
  "directoryId": "22222222-2222-4222-8222-222222222222",
  "accessToken": "REPLACE-WITH-APPROVED-ORG-API-KEY"
}
```

Replace these sample IDs with the reviewed IDs. Keys are Bearer credentials;
a normal Jira email/API-token Basic-auth combination is not this API's
[authentication contract](https://developer.atlassian.com/cloud/admin/organization/rest/intro/#auth).
Unscoped organization admin keys are broad administrative credentials. The current
search operation's OpenAPI entry does not specify its granular scope, so verify
that the selected scoped key is authorized for this exact operation during the
live test. The reader does not broaden permissions or fall back on 403.

The implementation uses the non-mutating POST search operation at
`https://api.atlassian.com/admin/v2/orgs/{orgId}/directories/{directoryId}/users/search`.
The previous GET directory-user endpoint is deprecated and scheduled to stop on
June 30, 2027. Crucially, the path parameter alone does not restrict results to one
directory: every search body also contains `directoryIds: [directoryId]` and
`limit: 100`. The `-` identifier that expands to all directories is rejected.
Cursors remain JSON data sent back to the same fixed endpoint; links are not
followed as URLs.

The snapshot retains only account ID and the separately supplied account,
membership and composite statuses. Missing optional statuses remain null; no
active state is invented. Names, emails, avatars, role details and activity links
are omitted. The CLI emits the selected organization/directory and observed user
count. This is a directory observation, not proof of Jira/Confluence entitlement,
billing, purchased seats or activity. The API contract is authoritative for its
directory filter; no local company or user identity is inferred from the result.

## GitLab.com billable group members

Use a reviewed access token whose user has the **Owner** role for the selected
top-level group and can read its billing-member endpoint. GitLab documents
`read_api` for read access; a live test must confirm the specific token and owner
permission. The reader never requests a broader scope after a denial.
[Bearer headers are supported for personal/group/project tokens](https://docs.gitlab.com/api/rest/authentication/).
No CI job/deploy-token authentication or account impersonation is implemented.

```json
{
  "schemaVersion": 1,
  "provider": "gitlab-cloud",
  "consentReviewed": true,
  "groupId": "123456",
  "groupPath": "REPLACE-WITH-TOP-LEVEL-GROUP-PATH",
  "accessToken": "REPLACE-WITH-APPROVED-OWNER-TOKEN"
}
```

The group ID is a positive canonical decimal string within JavaScript's safe
integer range. The exact top-level group path is checked against group metadata.
A non-null or absent `parent_id`, mismatched ID, or mismatched full path rejects
the binding before billing data is requested. Subgroups are not supported by the
[billable-members endpoint](https://docs.gitlab.com/api/group_members/#list-all-billable-group-members).

Only `https://gitlab.com/api/v4/groups/{id}` and its `/billable_members` endpoint
are used, both with GET. Group metadata uses `with_projects=false` to avoid
retrieving project inventories; other group metadata such as runner tokens is
dropped by the typed projection and is never sent to Node or the CLI. GitLab Self-Managed and Dedicated hosts are not included
in this initial reader. A denied billing request does not fall back to the public
member list, since membership is not equivalent to being billable.

The reader follows GitLab's supplied offset-pagination Link only after verifying
origin, exact group path, next consecutive page and fixed page size. Duplicate or
unknown query parameters, userinfo and fragments reject the continuation. Header
counts are checked when provided; changing totals or a final count mismatch reject
the capture. Without a total, a full final page without a next link is rejected as
ambiguous. No URL from a member's avatar or profile is followed.

Only numeric user ID, username and supplied state/membership type are retained.
The CLI returns group binding and observed billable-member count without member
identities. The provider endpoint includes subgroup/project members; the count
is not the number of contracted, free or newly purchased seats. There is no
automatic removal, invitation, activation, database import or local identity link.

## JetBrains: instance contract still required

No JetBrains connector is enabled by this release. The official
[standalone License Vault Cloud documentation](https://www.jetbrains.com/help/license-vault-cloud/License_Vault_API.html)
requires the Swagger contract from the administrator's actual Vault. It uses a
Bearer access token. [IDE Services](https://www.jetbrains.com/help/ide-services-cloud/rest-api.html)
uses a separate License Vault Public Swagger contract and Automation-token
convention; its private endpoints are explicitly not stable APIs. We need the
selected product variant, instance URL and the public API contract before writing
a matching client. An unrelated example deployment is not a substitute for that
binding. No Vault token was generated, replaced or revoked.

## Run the probe

Use a one-off container from the policy-service image with the selected JSON
mounted read-only at `/run/opendirectory/provider-read.json`. The file must be a
regular file owned by the executing UID, with no group/other permissions
(recommended mode `0600`). Symlinks, foreign ownership, unknown fields and files
larger than 64 KiB reject startup. For Kubernetes, use the existing
`prepare-credentials` init-container pattern to copy projected Secret files into
regular UID-owned files; direct Secret-volume symlinks are intentionally rejected.
Set only the path as an environment variable:

```sh
LICENSE_PROVIDER_PROBE_CONFIG_FILE=/run/opendirectory/provider-read.json \
  node scripts/license-provider-probe.js
```

No database connection or OpenDirectory bearer is needed. The Google JWT/key and Adobe client secret
stay in Node; only the resulting access token and selected resource identifiers
cross private stdin into Rust. The child has an empty inherited environment.
Provider errors are reduced to stable codes; provider error bodies are not printed. The CLI success contains counts
and the customer/product/SKU or organization binding, not individual identities.
For example:

```json
{"ok":true,"provider":"google-workspace","customerId":"C01234567","productId":"Google-Apps","skuId":"1010020027","assignedUsers":12}
```

```json
{"ok":true,"provider":"github-copilot","organization":"your-organization","billedSeats":12,"pendingCancellations":1}
```

Exit code 1 means no successful capture. `google_token_http_400` commonly requires
checking the delegated subject, domain-wide delegation, selected OAuth client ID,
key and enabled API. 401/403/404 require checking the actual token permissions and
resource binding. Throttling returns a bounded `retryAfter`; wait before another
manual attempt. GitHub's 403 rate-limit headers are distinguished from ordinary
403 authorization failures. There are no automatic retries, fallback grants or
broader-scope requests.

## Integrity and limits

- TLS is verified, redirects are rejected and provider hosts are fixed. Google
  page tokens are encoded query values; provider URLs and self links are not
  followed. GitHub page URLs are constructed locally and Link targets ignored.
- A capture is bounded to 1,000 rows, 16 pages, 256 KiB per response, a 1 MiB
  process reply and a 20-second parent deadline. Limit violations reject the
  whole capture; they never return a successful truncated count. Increase these
  reviewed limits with tests before onboarding a larger organization.
- Google requires an identified collection for empty results; missing `items`
  on that collection follows Google's empty-list representation. Null collections,
  wrong SKU/product rows, duplicate users and cyclic page tokens reject.
- GitHub requires an exact page size, a stable reported total and unique numeric
  IDs/logins. Changed totals, partial pages and invalid cancellation dates reject.
  Neither provider offers an atomic snapshot across this pagination; concurrent
  changes can still affect a capture. These reads are not allocation evidence or
  manufacturer-confirmed purchased capacity.
- Adobe additionally limits metadata to five pages; its other response and process
  bounds are the same. Slack starts with an authenticated directory-scope check.
- Rust HTTP fixtures, signed Google JWT verification, Adobe S2S form validation, protected-file checks,
  Node process contracts, namespace mismatches, cancellation, response limits and
  rate-limit cases are tested locally. No real tenant connection or write was
  exercised. Authentication for the CLI is separate from onboarding a governed
  OpenDirectory company/provider integration.

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`
in this directory, plus the policy-service `ProviderReadClient.test.js` suite.
