# OpenDirectory

Self-hosted, open-source enterprise platform combining Active Directory, MDM, and Privileged Identity Management across all major operating systems.

## Current Product Direction

OpenDirectory is being developed into an **Apple Business-inspired business-management platform**: simple company onboarding, people and groups, devices, blueprints, applications and licenses, followed by locations, marketing and other business services. Entra-like IAM and least privilege remain part of that platform, not its entire product scope. The existing Next.js/Node.js/PostgreSQL stack is retained; there is no parallel Laravel/Vite rewrite.

The [product vision](docs/business/product-vision.md), [requirements](docs/business/business-requirements.md), [architecture](docs/architecture/architecture.md), [Apple capability matrix](docs/integrations/apple-capability-matrix.md) and [actual implementation status](docs/implementation-status.md) distinguish implemented components from prototypes and outstanding end-to-end workflows. This is **not yet a production-ready multi-tenant SaaS or an accepted Apple integration**. The location view no longer presents invented sites or simulated saves as real data.

The first [implemented business slice](docs/features/organization-profile.md) adds the real own-company profile at `/organization`: PostgreSQL persistence, original-actor/tenant-bound GET/PUT, fresh MFA, conditional ETags, immutable audit and pending outbox. [Bounded profile delegation](docs/features/organization-delegations.md) lets ordinary own-tenant users edit only that profile without global administration. [Company registration](docs/features/company-registration.md), [independent platform review](docs/features/company-registration-reviews.md) and [own applicant activation/MFA/first login](docs/features/company-activation.md) connect to the [own directory](docs/features/company-directory.md). That owner can manage own-tenant employee records and groups, [create/edit/move/retire organizational units](docs/features/organization-units.md) and [explicitly assign employees to multiple units](docs/features/organization-memberships.md) through conditional/audited APIs, without a global role. Memberships use actual authorized employee search, exact relationship IDs and controlled removal; active dependencies prevent user/unit deletion. Employee credentials and custom roles, scoped authority, devices or licenses are not inferred from a membership. Registration and activation remain separately disabled by default. [Generated OpenAPI 3.1](docs/api/openapi.yaml) covers these implemented paths. Account self-signup, complete company administration, external verification, connected employee/device/license workflows and production acceptance remain open.

## What is OpenDirectory?

The [real own-company device inventory](docs/features/device-inventory.md) now connects employee records to persistent devices: explicit tenant ownership, bounded original-token/MFA authority, conditional exclusive assignment/reassignment/release, retained history and actual pending outbox. `/devices` and the normal device-service runtime use this canonical inventory receiver. Devices remain **inventory only, not enrolled, compliance unknown**; old unowned rows are not automatically adopted. No successful MDM command or license allocation is inferred. Coordinated identity/device/gateway/frontend images and device migration 005 are required; connected provider, scope and JML workflows remain open.

OpenDirectory is an open-source alternative to Microsoft Intune, Azure Active Directory, and Jamf Pro. It gives organisations full control over their directory, device fleet, and identity infrastructure without vendor lock-in or per-seat licensing fees.

The platform runs on-premises or on Kubernetes and manages the full lifecycle of enterprise IT: domain controllers, user and group provisioning, device enrollment and compliance, group policy, privileged access management, certificate authority, and audit logging — all from a single interface and a unified REST/gRPC API.

OpenDirectory is built for teams that need the capabilities of a Microsoft 365 + Intune stack but want to own the data and the deployment. It is not a thin wrapper around existing tools; it ships its own Samba domain controller integration, Kerberos KDC service, LDAP proxy with schema management, GPO engine, and PIM service with session recording.

Development direction: an Entra-like identity and access platform with least privilege as the default, delegated administration, and lifecycle-based license distribution. The [identity governance plan](docs/features/identity-governance.md) distinguishes the target capabilities from what is implemented. Current increments add delegated license roles, independent approval, authenticated self-service, hardened token issuance, transactional direct/group allocation with overlapping-source reconciliation, local license recovery on offboarding/expiry, and task-specific quick-actions permissions with bounded consent and capability-based controls. Private license operations require explicitly linked, enabled canonical directory identities; token aliases and legacy requests cannot bypass independent review. Versioned directory checks validate direct recipients and reconcile disabled/deleted users locally without silently restoring direct grants. Microsoft 365/vendor provisioning, automatic identity linking/workload credential refresh, and outbox delivery remain planned.

The former `/api/license` prototype is now an optional canonical compatibility adapter, not a second allocator. It requires canonical payloads and retires unsupported SAM operations and the unrestricted WebSocket stream explicitly. Existing prototype data/keys need a reviewed migration; the modern kiosk uses policy-service directly.

The core gateway now verifies issuer, API audience and access-token purpose, with delegated control-plane permissions and no shared-key/cookie/query authentication or positive-auth cache. Identity and policy services enforce the same audience directly. Old gateway keys are retired, metadata requires persistent storage, and the integration UI respects verified capabilities. WebSocket support is header-authenticated native access, not a complete browser event feed; webhook tests are unsigned and deny outbound delivery by default. Cross-store identity/PIM propagation, tenant/resource isolation and production rollout remain outstanding. See the plan's tenth increment for migration and Lite-topology limits.

OAuth token revocations and refresh/session families now persist in PostgreSQL and are checked live by the core gateway, identity-service and policy-service, including direct API calls. Scoped self-service and narrow session administration terminate whole families; refresh reuse also revokes siblings. Authority failures deny access; idle native WebSockets close on family revocation/outage. OAuth signing requires pre-provisioned protected key files and supports reviewed public-key overlap; production never generates an ephemeral fallback. Fresh-process tests verify access/refresh continuity and key rotation at the hardened receivers. Independent credential/PIM propagation, legacy non-OIDC roles, remaining receivers and vendor provisioning remain unimplemented. See increments eleven–thirteen for scope, secret provisioning, breaking-token migration and real cross-service PostgreSQL coverage; no deployment is claimed.

The web application now signs in through a confidential token-mediating backend: server-side code exchange, S256/state/nonce verification, encrypted HttpOnly refresh cookies, in-memory access tokens and confirmed family logout. Forged `auth_user`/localStorage values no longer bypass the guard. Tab-coordinated refresh and authority failures are covered by an actual Chrome → Next.js → issuer → PostgreSQL gate, using a disposable credential-service fixture. This is not a full BFF, XSS immunity, federated end-session protocol or complete browser session-administration UI. Protected secret files and explicit client registration are required; see the [fourteenth increment](docs/features/identity-governance.md#fourteenth-implemented-increment-confidential-browser-token-mediation).

Canonical directory disable/delete/unlink and explicit authorization resets now fence existing human access, refresh and pending authentication grants at the issuer and the three live-checking resource boundaries. Re-enabling/relinking does not revive old grants; a new verified login is required. A narrowly scoped signed workload read avoids an identity ↔ issuer introspection cycle. Every human subject needs an approved canonical identity link before upgrade/bootstrap; old tokens are not silently migrated. Independent password/PIM stores, legacy role/provider/provisioning backends and remaining receivers are not yet unified. See the [fifteenth increment](docs/features/identity-governance.md#fifteenth-implemented-increment-live-directory-authorization-fences) for migration, timing, bootstrap and evidence.

The main browser user console now uses canonical users/groups, verified capabilities, real profile/status/reset/delete operations and disabled-by-default record creation. It no longer substitutes sample administrators or an LLDAP read on failure. Exact record-version preconditions prevent stale profile edits from undoing an account lock; transactional audit accompanies writes. Creation is not credential/role/MFA provisioning, and existing PUT/DELETE clients must adopt ETags. See the [sixteenth increment](docs/features/identity-governance.md#sixteenth-implemented-increment-canonical-user-console-and-conditional-writes) for migration and actual browser/database evidence. Independent credential/provisioning and password/PIM sources remain planned; no production deployment is claimed.

Human OIDC roles now come from audited canonical assignments rather than the credential service's role/permission response. The real role console supports separately delegated readers/managers, canonical self-administration denial, protected global delegation and grants lasting at most eight hours. Fresh source fingerprints enforce role expiry/revocation at the issuer, gateway and direct identity/license boundaries; regranting cannot revive old sessions. Migration 007, reviewed offline bootstrap and reauthentication are required. Tenant scopes, independent credentials/legacy non-OIDC paths and real vendor fulfillment remain open; the following increment adds eligible-role activation. See the [seventeenth increment](docs/features/identity-governance.md#seventeenth-implemented-increment-canonical-expiring-runtime-roles).

Canonical PIM now distinguishes eligibility, independent approval and owner activation. Only confirmed activation writes a bounded lease into the real role authority; the actual license API enforces its subsequent grant and withdrawal. Protected staff roles, no canonical self-approval, fresh authentication, live requester/reviewer fences and atomic audit replace the main console's unrelated group/request active labels. Migration 008 is required; no legacy PIM/group data is guessed or imported. Verified MFA/conditional access, mandatory-PIM policy, tenant scopes, legacy backend retirement and vendor fulfillment remain open. See the [eighteenth increment](docs/features/identity-governance.md#eighteenth-implemented-increment-eligible-roles-independent-review-and-real-activation) for scope, migration and actual three-actor browser/API evidence.

Quick-actions now checks live token/session/directory/role state at entry and before every delegated HTTP step, forwarding the original operator rather than substituting service credentials. Revocation, expired PIM, source failure, receiver denial or a closed caller ends that request's delegation; partial application creation cannot display a successful receipt or expose an unconfirmed secret. Optional Compose packaging and gateway routing remain disabled by default. Actual issuer/PostgreSQL and Chrome/Next tests cover the chain against recording HTTP receivers, not deployed AD/Kerberos/credential backends. Receiver-side authorization, durable reconciliation, canonical application provisioning and vendor fulfillment still need work. See the [nineteenth increment](docs/features/identity-governance.md#nineteenth-implemented-increment-live-actor-preserving-orchestration).

OAuth/OIDC registrations now use one live PostgreSQL client authority rather than a per-process registry. Delegated application readers/managers, protected role/administrative scopes, disabled-by-default creation, exact conditional writes, atomic audit, one-time secret disclosure and hashed secret storage replace the OAuth demo tab. Client changes, rotation and deletion fence access, refresh and pending sign-ins at the integrated receivers, including actual license writes; re-enabling cannot revive old grants. Migration 007 is breaking and requires reauthentication. This is not yet unified AD/Kerberos service-principal provisioning, tenant/app-consent governance or vendor licensing. See the [twentieth increment](docs/features/identity-governance.md#twentieth-implemented-increment-canonical-live-oauth-applications).

Human OAuth sign-in now requires an explicit, expiring canonical user/group assignment, including for administrators. Separate application-access readers/managers need neither client-secret nor profile-list authority. Fresh assignment and membership-incarnation checks fence access, refresh and pending login/device grants; remove/readd or regrant cannot revive old sessions. The real access console and bounded, audited offline bootstrap are tested against actual issuer/identity/PostgreSQL state. Identity migration 009 and OAuth migration 008 require reviewed bootstrap and reauthentication; no existing users are automatically assigned. App-role consent, tenant scopes, complete legacy receiver enforcement and vendor-backed licenses remain open. See the [twenty-first increment](docs/features/identity-governance.md#twenty-first-implemented-increment-mandatory-user-and-group-application-access).

Human OAuth authentication now supports a persistent, issuer-verified TOTP factor and real own-account setup instead of prototype MFA statistics. Session-bound enrollment, atomic anti-replay/throttling, protected encrypted secrets and live factor incarnations fence old access/refresh and pending sign-ins after a factor change. PIM activation requires a verified password-plus-code login no older than five minutes, not a claimed MFA flag. OAuth migration 009, a separately protected persistent encryption key and reauthentication are breaking requirements. Passkeys, reviewed lost-factor recovery, global conditional-access/mandatory-PIM policy and legacy MFA consolidation remain open. See the [twenty-second increment](docs/features/identity-governance.md#twenty-second-implemented-increment-verified-mfa-and-factor-backed-pim).

Owner-held MFA recovery now uses eight explicitly generated one-time backup codes, stored only as canonical-user-bound hashes. Password plus one backup allows only a short-lived new-factor setup; it never creates an application session, bypasses the upstream provider, grants a role or disables MFA. A proven replacement fences old strong access/refresh and pending sign-ins, then requires normal fresh MFA login. The real own-account and signed-out recovery screens, transactional audit/replay controls and fixed native token-mediator routes are tested against actual browser/issuer/directory/PostgreSQL state. OAuth migration 010 is required. Lost-all-factors helpdesk recovery, notification delivery, passkeys, tenant policy and vendor-backed license fulfillment remain open. See the [twenty-third increment](docs/features/identity-governance.md#twenty-third-implemented-increment-purpose-limited-owner-mfa-recovery).

Applications can now require verified canonical MFA and a bounded original authentication age. Separate protected authentication-policy duties, fresh MFA, exact client versions and audited reasons govern changes; registration editing cannot silently weaken the rule. Live access/refresh and pending grants use the current policy, and refresh cannot renew its proof. Assigned unenrolled users can register only a factor through a signed-out, purpose-limited first-binding flow, then must sign in normally. OAuth migration 011 and coordinated issuer/directory/web updates are required. Policies remain explicit opt-in, not tenant-wide/role-wide security defaults or vendor-license provisioning. See the [twenty-fourth increment](docs/features/identity-governance.md#twenty-fourth-implemented-increment-application-mfa-and-authentication-age-policies).

Canonical roles now have client-independent MFA and original-authentication-age policies. The strongest applicable live role rule also applies when a client omits `roles` scope, and weakening/reapplying policy cannot revive earlier sessions or pending grants. Separate protected policy administration has a fixed five-minute MFA minimum; application/role editors cannot acquire it implicitly. Assigned first binding also supports role-required MFA without issuing an application session. The real role console and actual license APIs enforce this across normal browser/API paths. Identity migration 010, coordinated issuer/directory/web images and human reauthentication are required. Other role policies require reviewed opt-in; universal security defaults, mandatory PIM and Microsoft license fulfillment remain open. See the [twenty-fifth increment](docs/features/identity-governance.md#twenty-fifth-implemented-increment-client-independent-role-authentication).

An opt-in Microsoft Graph fulfillment plane now connects reviewed local user entitlements to explicitly mapped tenant/user/SKU identifiers. Transactional desired-state evidence, an independent credential-bearing worker, fresh canonical eligibility checkpoints and observed provider confirmation replace success-only license forwarding. Separate protected configuration/adoption and retry duties do not inherit from ordinary license administration. Unknown outcomes, foreign/group assignments and plan drift are not silently retried, adopted or called provisioned. Both Compose variants have an off-by-default, no-ingress worker profile with owner-protected file credentials and a separately constrained database identity. Policy migration 009, identity migration 011 and coordinated images are required. Tests use owned HTTP provider fixtures, not a live Microsoft tenant; tenant acceptance, service-level provisioning verification and other vendors remain open. See the [twenty-sixth increment](docs/features/identity-governance.md#twenty-sixth-implemented-increment-durable-microsoft-license-fulfillment).

Canonical roles can now require independently approved, fresh-MFA-backed PIM activation instead of direct grants. Versioned role policies cap lease duration and permanently invalidate earlier grants and requests, including after relaxation. Separate protected policy duties have no assignment/approval/license powers. Global administrators have no direct-grant bypass; mandatory global administration requires explicitly named independent PIM reviewers and an existing eligible activation path. The actual PIM console uses conditional writes and explicit withdrawal acknowledgement. Identity migration 012, coordinated directory/web images and human reauthentication are required. Policies are reviewed opt-in, not universal privileged defaults or a replacement for tenant scopes and access reviews. See the [twenty-seventh increment](docs/features/identity-governance.md#twenty-seventh-implemented-increment-mandatory-privileged-activation-policies).

Canonical role grants and PIM eligibilities now support recurring, independent access reviews. Protected review configuration and voting duties are separate; named reviewers need fresh verified MFA and cannot certify themselves, including global administrators. Accepted deadlines constrain the live role source without a privileged scheduler. Retention advances only the review cycle, not the base grant; withdrawal changes the actual canonical grant. Retirement/replacement cannot revive expired rights, and decisions bind both lease and policy versions. Identity migration 013 and coordinated directory/shared-contract/web images are required. This first review plane governs roles, including who can administer licenses; recipient license/application/group reviews remain further work. See the [twenty-eighth increment](docs/features/identity-governance.md#twenty-eighth-implemented-increment-recurring-independent-role-access-reviews).

Direct license grants and whole group rules now have immutable source incarnations and versioned lineage. Fresh-MFA-backed conditional withdrawal preserves overlapping grants and commits seat/provisioning desired-state changes atomically; a retired group cannot be restored by automatic reconciliation. The license kiosk confirms the actual group source and version instead of deleting by recipient alone. Policy migration 010 and coordinated policy/web images are required. This source-aware foundation supports the recurring review plane below; local receipts still do not confirm Microsoft removal. See the [twenty-ninth increment](docs/features/identity-governance.md#twenty-ninth-implemented-increment-versioned-license-source-lineage-and-conditional-withdrawal).

Human license sources now support recurring, independent reviews. Separate protected configuration/voting roles require fresh real MFA; readers have no allocation powers. An unanswered cutoff constrains effective local entitlement without a privileged review scheduler. Retention advances only the review cycle, while denial removes the exact direct source or disables its whole group rule, preserving overlaps. Retirement/replacement cannot revive expired sources or extend an accepted cutoff. Policy migration 011, identity migration 014 and coordinated issuer/directory/gateway/policy/worker/web images are required. This is opt-in human license-source governance, not device/application/tenant review coverage or instantaneous vendor removal. See the [thirtieth increment](docs/features/identity-governance.md#thirtieth-implemented-increment-recurring-independent-license-source-reviews).

License administration can now be delegated for one human license pool at a time. Separate control-plane and delegate roles, bounded reader/allocator/approver leases, fixed fresh MFA and canonical role/lifecycle incarnations prevent a pool grant from becoming global license authority or reviving after reactivation. The kiosk uses a distinct scoped API; expiry removes administrative authority, not licenses already allocated. Policy migration 012, identity migration 015 and coordinated images are required. Tenant isolation, scoped PIM and delegation access reviews remain open. See the [thirty-first increment](docs/features/identity-governance.md#thirty-first-implemented-increment-resource-scoped-license-administration).

Pool-scoped PIM now separates eligibility, independent review and explicit owner activation. A bounded eligibility grants no active rights, a named protected reviewer cannot self-approve, and approval alone cannot allocate licenses. Activation rechecks both the holder's and original reviewer's canonical role/lifecycle and issuer-link incarnations; expiry, deactivation or parent revocation ends the actual scoped authority without removing business licenses already allocated. Policy migration 013, identity migration 016 and coordinated images are required; pre-link-bound pool proofs need explicit retirement and independent reissue, not silent historical rewriting. Standing grants remain possible; mandatory per-pool PIM policies and tenant isolation are not implemented. See the [thirty-second increment](docs/features/identity-governance.md#thirty-second-implemented-increment-independently-approved-pool-scoped-activation).

Versioned pool policies can now require approved PIM for a selected duty. Policy administration is separate from eligibility configuration and voting, needs fresh real MFA and an independently prepared live activation path, and permanently fences older grants/requests even after relaxation. Allocator/approver requirements also govern global and compatibility license mutations and suppress automatic approval; existing licensed group derivation, expiry, offboarding and independent source-review withdrawal remain operational. Reader policy governs delegated reader grants, not global catalog confidentiality. Policy migration 014, identity migration 017 and coordinated images are required; enforcement is deliberate opt-in, not automatic for every pool or tenant isolation. See the [thirty-third increment](docs/features/identity-governance.md#thirty-third-implemented-increment-versioned-mandatory-pool-activation-policies).

Delegated pool grants and PIM eligibilities now support independent recurring administrative reviews. Separate protected configuration/voting roles need fresh real MFA; holders, original grantors, activation reviewers and policy authors cannot self-certify. Unanswered deadlines remove actual authority without a scheduler; denial revokes the target, not recipient business licenses. Retention never extends base expiry or earlier PIM activations, and retirement/replacement cannot reset accepted cutoffs. The kiosk shows own effective cutoffs, assigned decisions and known-ID read-only evidence. Policy migration 015, identity migration 018 and coordinated images are required. Tenant isolation, mandatory defaults, notifications and live Microsoft acceptance remain open. See the [thirty-fourth increment](docs/features/identity-governance.md#thirty-fourth-implemented-increment-recurring-delegation-and-eligibility-reviews).

Canonical flat-group memberships now support independent first approval and recurring reviews. In an explicitly governed group, a new configured link is not effective app or licensing authority until a named fresh-MFA reviewer approves it. Existing members receive an acknowledged first-response cutoff; unknown historical grantors require explicit reissue, not retroactive approval. Expiry withdraws canonical app membership immediately, and group-license reconciliation removes that source while preserving direct overlaps. Retirement cannot reopen unreviewed admission or reset old cutoffs. Identity migration 019 and coordinated directory/issuer/gateway/web images are required. The directory is still global, not tenant-isolated. See the [thirty-fifth increment](docs/features/identity-governance.md#thirty-fifth-implemented-increment-independent-and-recurring-group-memberships).

Group-derived license seats now have mandatory directory leases: at most five minutes from canonical observation, capped sooner by membership/business-review and source deadlines. The actual local entitlement expires even without a successful source poll or housekeeping; independent direct overlaps remain effective. The console displays stale evidence and warns about missing renewal. Identity migration 020 and policy migration 016 intentionally fence unobserved legacy group projections instead of inventing a fresh lease. Configure timely reconciliation and coordinate v2 source/receiver images before rollout. Remote removal still needs its separately configured worker and observation; no live Microsoft acceptance or tenant isolation is claimed. See the [thirty-sixth increment](docs/features/identity-governance.md#thirty-sixth-implemented-increment-outage-bounded-group-license-leases).

Unattended group licensing can now use dedicated OAuth client credentials with automatic access-token renewal and explicit expiring per-group/source-client-generation consent. The existing protected license-scope administrator confirms the exact client generation with fresh MFA; readers get only known-scope metadata. Source expiry caps the real local entitlement, client rotation cannot silently reuse old consent, and application tokens have no human allocation/profile rights. The kiosk provides confirmation and withdrawal without accepting secrets. Identity migration 021, policy migration 017, coordinated v3 images and an operator-provisioned owner-only `LICENSE_SOURCE_CONFIG_FILE` are required. This is not automatic secret/consent renewal or tenant isolation. See the [thirty-seventh increment](docs/features/identity-governance.md#thirty-seventh-implemented-increment-scoped-workload-source-consents-and-automatic-tokens).

The canonical policy receiver now defaults to deny: ordinary sign-in, licensing duties and workload source tokens cannot read or change device policy. Separate policy readers, configuration administrators and deployment operators use canonical roles; every configuration/deployment write requires fresh real MFA. The main policy console uses actual persisted data and confirmed responses instead of sample GPOs or optimistic success. GPO/blueprint delivery preserves the original operator with per-step live checks, never borrows the ambient internal token, and distinguishes queued commands from device enforcement. Identity migration 022 and coordinated issuer/policy/gateway/web images are required. This is not tenant isolation, independent policy publication approval or completed endpoint management. See the [thirty-eighth increment](docs/features/identity-governance.md#thirty-eighth-implemented-increment-default-deny-policy-operations-and-actor-preserving-delivery).

Policy configuration now uses mandatory exact-version mutations, atomic original-actor audit and pending outbox evidence. GPOs/update rings use real canonical policy records instead of seeded memory maps; blueprints and their children share a durable parent version. Source authority is rechecked after locks/DML, known MFA/token deadlines are enforced again at commit, and managed delivery stops when captured content changes. The policy/GPO and blueprint consoles use the new conditional contract, including refusal of down-level receiver capabilities before writing. Policy migration 018 and coordinated protocol-v2 policy/web images are required. Pending events are not delivered notifications, and this is not independent publication approval, tenant isolation or confirmed endpoint enforcement. See the [thirty-ninth increment](docs/features/identity-governance.md#thirty-ninth-implemented-increment-conditional-policy-configuration-and-atomic-evidence).

Canonical activation and managed GPO/blueprint delivery now require an explicit, independently approved, content-and-target-bound publication. A separate protected `policy-publication-reviewer` duty cannot edit, deploy, allocate licenses or read directory profiles. Requesters and every retained content/target contributor are excluded from reviewing their own configuration. Exact request/resource versions, bounded deadlines, current requester/reviewer authority, atomic audit and pending outbox fence stale approvals; content changes return policies to draft. Main policy/blueprint consoles support real request, independent vote, withdrawal and selection. Identity migration 023, policy migration 019 and coordinated protocol-v3 images are required; no reviewer is automatically assigned. This does not undo prior device effects or protect every direct/internal receiver path. See the [fortieth increment](docs/features/identity-governance.md#fortieth-implemented-increment-independent-content-bound-policy-publication).

The canonical device receiver now accepts policy commands only as exact approved references, deriving settings independently from policy-service with the original fresh-MFA operator. Even a global administrator cannot post arbitrary policy payloads, and an internal/service credential cannot bypass publication. Actual PostgreSQL command/origin/audit/outbox commits replace memory-first success; captured operation retries cannot exchange actor/content or extend deadlines. Generation-bound device credentials pull bounded durable offers and make immutable self-reported outcomes, not verified execution claims. Unreviewed automatic policy remediation and demo-device SQL seeding are retired. Issuer migration 012, coordinated policy protocol-v4 images and newly enrolled generation-bearing device credentials are required. This is not full device lifecycle governance, automatic cancellation of accepted work or complete workflow recovery. See the [forty-first increment](docs/features/identity-governance.md#forty-first-implemented-increment-receiver-bound-policy-commands-and-durable-device-receipts).

Deployers can now explicitly stop their own already accepted policy commands using the exact original SQL receipt, a captured cancellation operation, fresh canonical MFA and a reason. Cancellation, immutable actor/reason evidence, audit and pending outbox commit together; repeated captured operations reuse the same result. Device polling/reporting cannot reopen cancelled commands or erase completed outcomes. The blueprint console reloads bounded own-command history from SQL, including after a lost response or page reload, instead of relying on transient delivery results. Issuer migration 013 and coordinated issuer/web images are required. This is not automatic publication-triggered cancellation, authority over another operator's jobs or reversal of effects already received by a device. See the [forty-second increment](docs/features/identity-governance.md#forty-second-implemented-increment-owned-policy-command-cancellation-and-recoverable-receipts).

Manufacturer capacity now has a separate read-only Microsoft SKU observer and a bounded comparison in the license console. A protected file and explicitly provisioned connector-bound database identity replace ambient fulfillment credentials; the collector cannot read recipients, create local rights or change provider mappings. Complete observations, failures, audit and pending outbox are durable, with five-minute validity from capture start, source/connector-generation fences and connector-wide throttling. Unknown, missing, stale and paused inventory is never zero or guaranteed free capacity. Policy migration 020 and coordinated service/web/worker images are required; the optional `license-capacity` profile is off by default. The observation alone changes no pool size, buys no license and proves neither reserved vendor seats nor live Microsoft acceptance. See the [forty-third increment](docs/features/identity-governance.md#forty-third-implemented-increment-read-only-manufacturer-capacity-and-bounded-reconciliation).

Actual Microsoft additions now additionally require current inventory and an explicitly reviewed finite admission budget. SQL serializes charges across recipients, commits each charge with write intent/audit/pending outbox, and fences a one-time receipt immediately before POST. Captures, crashes, uncertain outcomes and ordinary retries never replenish the quota; removals do not require capacity. Budget rebasing is a conditional offline schema-owner review, not a license-manager API grant or automatic paid-pool adjustment. Migration 021, renewed narrow worker grants and coordinated policy/web/worker images are required; old-protocol addition intents fail closed. The console distinguishes observed stock from retained quota charges. These are local admission limits, not exclusive Microsoft reservations or distributed SQL/Graph transactions. See the [forty-fourth increment](docs/features/identity-governance.md#forty-fourth-implemented-increment-conservative-vendor-write-admission).

Canonical tenant ownership now has an explicit lifecycle anchor: identity migration 024 creates no default owner and adopts no old records automatically. Reviewed offline scripts bind existing users/groups/OUs immutably, reject mixed references and advance actual authorization/eligibility generations on adoption or parent pause/re-enable. Unowned/paused people cannot create positive canonical sign-in or eligibility authority; old sessions/pending human grants cannot revive on re-enable. Coordinated images and reviewed bootstrap adoption are breaking rollout requirements. **This is not complete multi-tenant isolation:** global directory/policy/role operations, client/pool/provider/device ownership and general receiver boundaries remain open. Do not deploy it as an isolated shared-customer service. See the [forty-fifth increment](docs/features/identity-governance.md#forty-fifth-implemented-increment-canonical-tenant-ownership-and-lifecycle-anchor).

Subject-link administration now derives the target tenant from an uncached, original-token-bound issuer proof, not caller-supplied ownership or an `admin` label. Identity migration 025 retains the issuer/subject's immutable tenant even after unlink or user deletion, refuses foreign/unowned targets and records atomic audit/pending outbox evidence. Original authority is checked after locks and DML; local generations, roles and token/MFA deadlines are checked again at commit. Self-unlink requires another operator. Positive identity-source protocol v6 is mandatory; v5 cannot supply tenant authority. Coordinate identity/issuer images and configure `OIDC_TENANT_STATE_URL` for native installations. This closes the subject-link receiver only, not the remaining global directory/resource planes. See the [forty-sixth increment](docs/features/identity-governance.md#forty-sixth-implemented-increment-tenant-bound-subject-link-administration).

Ordinary directory GETs now use the original token's tenant in SQL: users (including counts/pages), groups and member IDs, OUs/trees, aggregate search and user-role history. The receiver checks canonical identity/role/tenant state in one read-only snapshot and rechecks original live authority before releasing data; no demo-memory fallback supplies tenant data. The main user/role consoles require read protocol 1 before targeted reads, so older receivers cannot silently supply global data. This uses migration 025 and the existing issuer tenant-state endpoint, with coordinated identity/web images. Existing-resource write isolation and other licensing/device/policy/client planes remain open. Historical/raw unowned records remain invisible until explicit offline adoption; canonical creation is addressed separately below. Do not deploy it as isolated shared-customer hosting. See the [forty-seventh increment](docs/features/identity-governance.md#forty-seventh-implemented-increment-tenant-bound-ordinary-directory-reads).

Canonical POST creation of users, groups and OUs now derives its immutable owner from the verified original human actor. Migration 026 commits actual new rows, ownership and verified-actor audit/pending outbox together, rejects existing/retired UUIDs and foreign OU parents, and preserves disabled-first users and empty groups. Original authority is checked after locks/DML, with deferred local role/deadline/content fences. A matching SQL receiving receipt is mandatory, so a missing creation guard cannot produce a fake owned success. The main user console negotiates creation protocol 1 before POST. Coordinate identity/web images and apply migration 026; no caller tenant, fake default company, demo-memory creation or automatic adoption of old records is accepted. Existing-resource write isolation is addressed separately below; memberships, role writes and other resource planes still require tenant scopes. See the [forty-eighth increment](docs/features/identity-governance.md#forty-eighth-implemented-increment-original-actor-tenant-ownership-for-new-resources).

Canonical existing-user profile/status changes, session invalidation and deletion now derive their target scope from the original token's tenant. Migration 027 binds exact locked before/expected-after state, original actor, immutable mutation evidence and pending outbox in one transaction; foreign/unowned targets stay hidden even from global administrators. Strong profile/delete ETags remain required. Legitimate own disable/reset/delete retains normal issuer revocation checks, produces retained evidence and ends old sessions after commit. The main user console requires user-mutation protocol 1; coordinate identity/gateway/web images and migrations 024–027. The gateway preserves canonical directory paths, configured identity URL and version headers. Group/OU writes, memberships, role writes and other resource planes are not yet completely tenant-isolated. See the [forty-ninth increment](docs/features/identity-governance.md#forty-ninth-implemented-increment-tenant-bound-existing-user-mutations) for receiving invariants, current verification and remaining limits.

The **Gruppen** page now uses actual canonical directory data instead of sample administrator/dynamic/distribution groups. Public group profile/member/delete operations use original-token tenant scope, exact group ETags and mandatory atomic receiving evidence. Independent membership-review configuration, queues and decisions have the same tenant boundary, including referenced reviewers and retained source provenance. The server advertises separate mutation/review protocol 1; older receivers leave the corresponding controls disabled. Coordinate identity/web images and migrations 028/029. The 4,076-case group verification passes; evidence is tracked in the [implemented canonical group increment](docs/features/identity-governance.md#fiftieth-implemented-increment-canonical-tenant-bound-group-management). This is not complete platform tenant isolation or confirmation of external license delivery.

The gateway now lets originless production callers reach normal bearer/live-state authorization instead of rejecting them at CORS. Browser origins remain explicitly allowed, empty/`null` origins fail closed, and all proxy responses retain the gateway's CORS decision rather than a downstream wildcard. ETags, original bearers and conditional-write statuses are preserved. The native production-mode gate and complete 249-case signed regression pass, with evidence in the [production transport increment](docs/features/identity-governance.md#fifty-first-implemented-increment-production-gateway-transport); this is not a production deployment or a license-provider acceptance.

**Remaining authority-isolation gap:** mutable role-governance policies and the live legacy role source are not yet fully tenant-bound. A historical two-owner diagnostic demonstrated foreign role/eligibility creation. Migration 032 now adds an active **partial target fence**: canonical role/PIM foreign recipients and known requests are rejected, owned-user locks are scoped, and PIM queues filter ownership before limits. The [complete authority-boundary plan](docs/features/identity-governance.md#fifty-second-increment-in-progress-tenant-bound-authority-lifecycle) still requires owned policy/source publication, original-bearer receiving receipts and the real console cutover. Existing contaminated legacy grants are not automatically revoked; directory/group/target gates are not proof of safe shared-customer hosting.

Migration 030 and `npm run authority:review` now provide owner-only offline inventory/staging of complete reviewed migration **drafts**. Exact source/policy hashes, own reviewer references, inherited cutoffs, quarantine intentions and atomic pending evidence are validated; no draft can authorize access or be flipped active. Explicit review credentials/schema are required, with no application-database fallback. This prepares the complete cutover; it does not yet close the role/PIM gap or change existing licenses.

Migration 031 adds read-only, committed-draft source assessment (`authority:review -- plan CANDIDATE_UUID TENANT_UUID ISSUER`). It evaluates owned role proposals against the exact retained graph: foreign/quarantined sources, missing mandatory PIM/reviews, incompatible durations and inherited deadlines cannot silently become compliant roles. Output is explicitly non-authorizing `proposedRoles`, not a live authority envelope, publication approval or a change to current roles/licenses. The live resolver and complete receiving/UI switch remain outstanding.

The migration-032 target fence passes the [complete 4,248-case named regression](docs/features/identity-governance.md#complete-named-regression-for-the-target-fence) on migrations 001–032, including 251 actual signed issuer/receiver cases and 50 actual Chrome scenarios. Real own-tenant role/PIM and local license consoles remain usable; an added real-clock MFA test verifies stale-code denial without weakening verification. The 17 existing TypeScript diagnostics remain unresolved. This is neither a new scoped authority protocol nor production deployment or complete tenant-isolated governance.

Migration 033 adds [sealed owned policy bases](docs/features/identity-governance.md#implemented-owned-policy-bases-sealed-not-active): distinct tenant/namespace keys and independently versioned MFA, PIM and review components, with mandatory immutable offline evidence. Its targeted receipt covers 508 unit, 384 native identity and 11 actual production-mode cases, not the complete historical 4,248-case regression. Migration 034 adds the [sealed SQL source kernel](docs/features/identity-governance.md#implemented-sealed-source-kernel-not-live-authority): exact reviewed source IDs, current rows/audits, complete PIM/review components, preserved cutoffs and no global-policy fallback. Every result remains non-authorizing; no CLI/HTTP activation or live-role source switch is added.

The [migration-034 targeted gates](docs/features/identity-governance.md#migration-034-verification) pass **508 unit + 408 native identity + 11 actual production-mode cases**. The 24 new source cases include real approved/active PIM with both assignment and eligibility reviews. This is not an active owned authority protocol, a new UI feature, complete license governance or production approval.

The actual role/PIM/MFA write handlers add [original-bearer command checkpoints](docs/features/identity-governance.md#implemented-original-bearer-command-checkpoints-live-partial) before the transaction and after SQL effects: revoked/unavailable original authority rolls back rather than returning an earlier success, including legitimate self-change paths. Their migration-034 [complete named regression](docs/features/identity-governance.md#complete-named-regression-for-command-checkpoints) passes **4,317 cases**, including 265 signed issuer/receiver and 50 actual Chrome cases. Real PIM enables local license allocation; self-deactivation removes allocation authority without removing an existing business license. The 17 known TypeScript diagnostics remain.

Migration 035 adds [deferred SQL authority checkpoints](docs/features/identity-governance.md#implemented-deferred-authority-checkpoints-migration-035) to all five role/PIM/assurance/review management classes: original token/MFA deadlines, tenant/link incarnations, mandatory immutable evidence and pending outbox, plus no later canonical DML even after scope clearing. Its [complete named regression](docs/features/identity-governance.md#complete-named-regression-after-migration-035) passes **4,365 cases**, including 425 native identity, 267 full signed and 50 actual Chrome cases. The 17 known TypeScript diagnostics remain. The sealed owned source, exact pre-admitted command effects, legacy-writer cutover, distributed issuer revocation serialization and production/vendor acceptance remain open.

Migration 036 adds [typed owned source bases](docs/features/identity-governance.md#implemented-owned-source-bases-migration-036-not-active): immutable initial versions, independent owned policy references, ordered same-namespace edges, explicit unresolved/quarantine state and mandatory retained evidence. The sealed kernel requires committed materialization instead of candidate-JSON fallback; its private assessment version 2 still cannot authorize. The [targeted gates](docs/features/identity-governance.md#migration-036-verification) pass **549 unit + 445 native identity + 27 actual signed production-mode cases**, including 20 new SQL cases and existing PIM-to-local-license regression. Explicit current heads/history, active publication, the coordinated live source/receiving/console cutover and production/vendor acceptance remain open; the historical complete regression is not extended to this migration.

## Architecture

OpenDirectory is composed of approximately 30 microservices organised into three layers. Services communicate asynchronously through a pluggable gRPC event bus (RabbitMQ by default). Each service exposes a REST API and a `/health` endpoint, and emits Prometheus metrics.

```
Core Services                Enterprise Services          Platform Services
─────────────────────────    ─────────────────────────    ─────────────────────────
authentication-service       compliance-engine            api-gateway
enterprise-directory         audit-service                quick-actions
device-service               security-scanner             event-bus
policy-service               mobile-management            integration-service
conditional-access           app-store                    api-backend
least-privilege              graph-explorer
samba-ad-dc                  automation
kerberos-kdc                 policy-engine
ldap-proxy                   policy-simulator
notification-service         ai-analytics
certificate-authority        antivirus-protection
monitoring-service           auto-remediation
update-management            multi-tenant
backup-service               disaster-recovery
remote-control
oauth-provider
identity-service
```

**Databases:** PostgreSQL (primary operational store), MongoDB (directory objects and GPO data), Redis (session cache, distributed locks).

**Frontend:** Next.js / React 18 single-page application with an Apple Business Manager-style three-column layout.

## Features

### Active Directory and Identity

- Samba AD DC integration — full domain controller, LDAP, Kerberos
- LDAP proxy with schema management and a full LDAP REST gateway (RFC 4515 filter support)
- Kerberos KDC with constrained delegation (S4U2Self, S4U2Proxy, RBCD), ticket policies, and Protected Users group enforcement
- Forest and trust management — external, forest, shortcut, and Kerberos realm trust types
- Multi-DC replication monitoring with USN tracking and force-sync
- Fine-grained password policies and account lockout enforcement
- Organisational Units, Groups, Computer accounts (domain join and unjoin)
- LAPS (Local Administrator Password Solution) — per-device admin passwords, rotation, and audit log
- BitLocker recovery key escrow and retrieval with full audit trail

### Device Management (MDM)

- Unified device management across Windows, macOS, Linux, iOS, and Android
- Zero-touch enrollment per platform: APNS for macOS/iOS, WinRM for Windows, SSSD for Linux, QR code for mobile
- Bulk enrollment for fleet operations
- Remote actions: lock, wipe, restart, remote command execution
- Device compliance scanning and violation tracking
- Software deployment via enterprise app store
- Network profile deployment (Wi-Fi, VPN, email configuration)
- Backup and disaster recovery, per-device and domain-wide
- Geofencing zones with location-aware conditional access

### Group Policy and Configuration

- GPO engine compatible with Windows Group Policy concepts
- Resultant Set of Policy (RSoP) calculation per user or OU
- GPO enforcement with inheritance and Block Inheritance support
- Fine-grained account and password policies
- Configuration profiles for all managed platforms
- Update management: Windows Update, WinGet, macOS Software Update
- Policy baselines and blueprints

### Privileged Identity Management (PIM)

- Role-based just-in-time (JIT) access with configurable maximum duration
- Multi-level approval chains (sequential approvers per tier)
- Risk scoring based on time-of-day, request frequency, role sensitivity, and active elevations
- Break-glass emergency access with dual-control activation
- Session recording: every privileged action logged with risk score
- Session replay: full activity timeline for an elevation window
- Automatic AD group membership sync on elevation grant and revoke
- Event bus integration (`security.elevation.*` events)

### Security and Compliance

- Conditional access policies evaluated on device health, identity, location, and time
- Zero-trust scoring combining device, identity, network, and behavioural signals
- Compliance engine with baseline definitions and waiver management
- Security scanner for vulnerability assessment
- Antivirus protection management
- Auto-remediation for compliance violations
- Certificate authority: issue, renew, revoke
- Audit trail covering every directory change, authentication event, and GPO application

### Authentication and SSO

- Multi-factor authentication (TOTP, recovery codes)
- Single Sign-On via OIDC, SAML, and OAuth 2.0
- Session management: list, revoke, revoke-all
- Password reset workflows (SSPR)
- Service Principal management — create an application identity with ClientID, ClientSecret, and a Kerberos SPN in a single operation

### Developer Platform

- REST API across all services (400+ endpoints)
- gRPC event bus with pluggable transports (RabbitMQ, gRPC, in-memory for tests)
- Event routing registry (`config/event-routing.yaml`) with 50+ routing keys
- API gateway for unified external access
- Microsoft Graph-compatible API layer (graph-explorer service)
- Integration service for third-party systems
- Webhook and automation support

### UI

The frontend uses an Apple Business Manager-style three-column layout: sidebar navigation, item list, and detail panel.

- Device Fleet view: per-OS cards (macOS, Windows, Linux, iOS, Android) with click-to-filter and compliance indicators
- Enrollment Wizard: 4-step, OS-aware flow with platform-specific setup instructions
- Service Principal Wizard: one-click create returning ClientID, masked ClientSecret with reveal, and `.env` download
- User Onboarding Wizard: 4-step new-employee flow with temporary password reveal
- Policy Deploy Wizard: target by OS, OU, Group, Device, or User; dry-run mode; progress bar
- PIM view: Roles, Requests, Active Elevations, Session Replay, Break-Glass
- Audit Log view: filterable, paginated, severity colour-coded
- Compliance Snapshot: donut chart, top violations, devices needing attention
- Trust Management view: forest trust graph with verify, rotate, and remove actions
- Kerberos Admin view: delegation configuration, Protected Users group, ticket policies
- Replication Dashboard: per-DC health, USN tracking, force-sync, 30-second auto-refresh
- LAPS and BitLocker in device detail: password reveal with audit, key recovery modal

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js 18+, Express 4 |
| Event Bus | gRPC + RabbitMQ (pluggable via `@opendirectory/grpc-event-bus`) |
| Databases | PostgreSQL (primary), MongoDB (directory/GPO), Redis (cache/sessions) |
| AD/LDAP | Samba 4, LLDAP, ldapts |
| Kerberos | MIT Kerberos (kadmin API) |
| Frontend | Next.js, React 18, TypeScript |
| Container | Docker, Kubernetes (Helm chart included) |
| Monitoring | Prometheus metrics on every service, `/health` endpoints |
| Testing | Jest (unit + integration), nock (HTTP mocking), React Testing Library |

## Quick Start

### Prerequisites

- Docker and Docker Compose >= 20.10
- Node.js >= 18 (for local development)

### Run with Docker Compose

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
docker compose up -d
# UI:          http://localhost:3000
# API Gateway: http://localhost:8080
```

### Run on Kubernetes

```bash
helm install opendirectory ./deploy/helm/opendirectory \
  --set global.domain=opendirectory.local \
  --set postgresql.auth.password=<password> \
  --namespace opendirectory --create-namespace
```

## Services

| Service | Port | Description |
|---|---|---|
| authentication-service | 3001 | User auth, MFA, SSO, session management |
| enterprise-directory | 3000 | AD-compatible directory, GPO, OU management |
| device-service | 3003 | MDM, device lifecycle, compliance, remote actions |
| policy-service | 3004 | Policy engine, RSoP, templates, blueprints |
| conditional-access | 3007 | Conditional access evaluation, zero-trust scoring |
| least-privilege | 3011 | Permission matrix, PIM role management |
| samba-ad-dc | 3010 | Domain controller (Samba), trusts, LAPS, replication |
| kerberos-kdc | 3013 | Kerberos KDC, delegation, ticket policies |
| ldap-proxy | 8389 | LDAP proxy and schema management REST API |
| notification-service | 3006 | Email and push notifications |
| certificate-authority | 3015 | PKI, certificate lifecycle |
| compliance-engine | 3907 | Baseline evaluation, waivers, trend analysis |
| audit-service | 3908 | Event collection, audit log aggregation |
| security-scanner | — | Vulnerability assessment |
| mobile-management | — | iOS/Android MDM, Apple Business Manager integration |
| app-store | — | Enterprise app store |
| api-gateway | 8080 | Unified external API |
| quick-actions | 3950 | Orchestration: one-click SP, enroll, onboard, deploy |
| integration-service | — | Third-party integrations |
| monitoring-service | — | Prometheus metrics aggregation |

## Event Bus

Events are exchanged via `@opendirectory/grpc-event-bus`. The routing table lives in `config/event-routing.yaml`. Key namespaces:

| Namespace | Events |
|---|---|
| `device.*` | enrollment, compliance, commands |
| `policy.*` | create, activate, evaluate |
| `security.elevation.*` | PIM JIT grant and revoke |
| `security.breakglass.*` | emergency access activation |
| `directory.object.*` | AD CRUD events |
| `kerberos.*` | ticket and delegation events |
| `ad.trust.*` | trust create, verify, remove |
| `ad.replication.*` | DC sync and health events |
| `identity.*` | login, token, MFA events |

## Testing

- 780+ tests across all packages and services
- Unit tests: DDD aggregates, value objects, application services
- Integration tests: EventBusClient flows, saga patterns
- E2E API tests: all REST endpoints with supertest and nock
- Frontend component tests: React Testing Library

```bash
# Run all tests
npm test --workspaces

# Run a specific service
cd services/core/authentication-service && npm test
```

## Contributing

Pull requests are welcome. Please open an issue first for significant changes. All services follow the same pattern: Express router, application service layer, domain model, and Jest tests.

## License

MIT
