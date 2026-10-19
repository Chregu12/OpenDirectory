# OpenDirectory Roadmap — Outstanding Work

This document lists features that are planned or partially implemented but not yet production-ready.
Grouped by priority: Critical (blocks production use) → High → Medium → Low.

## Product Direction — Apple Business-Inspired Platform

The 19 October 2026 master prompt expands the product direction to company/organization management, people, devices, blueprints, apps/licenses, locations, marketing, analytics, subscriptions, support, collaboration and integrations. Preserve the existing stack and canonical data owners; do not start a parallel framework rewrite. The [new requirements](docs/business/business-requirements.md), [gap analysis and vertical delivery order](docs/implementation-status.md) are the primary product roadmap. The complete identity/least-privilege work below remains required but is not the whole product.

The [current-company profile](docs/features/organization-profile.md), [bounded profile delegation](docs/features/organization-delegations.md), [credential-bound registration](docs/features/company-registration.md) and [independent internal review](docs/features/company-registration-reviews.md) connect to [own applicant activation, mandatory MFA and first console login](docs/features/company-activation.md). The [own directory](docs/features/company-directory.md) adds own-tenant employee records and groups/memberships. [Canonical unit changes](docs/features/organization-units.md) replace the legacy unscoped writes with conditional edits, subtree moves and confirmed leaf retirement. [Real multiple user-unit relationships](docs/features/organization-memberships.md) add authorized name search, versioned assignment/removal and active deletion dependencies. No global role or complete Company-Administrator authority is implied. Next: controlled organizational scopes and connected employee/device/blueprint/license workflows; membership alone never provisions access or licenses. Locations, marketing, account self-signup/external verification and all remaining master-prompt requirements remain in scope. Unsupported providers and missing backends must not produce fake successes or metrics. These slices do not activate the sealed general owned role source or establish complete SaaS isolation or production readiness.

## Identity Governance and Least Privilege

The [own-company inventory slice](docs/features/device-inventory.md) now implements real device creation, exclusive employee assignment/reassignment/release and retained local history in the existing device-service PostgreSQL database. The new default runtime fails closed without migrations, negotiates an actual receiver contract and never claims enrollment/compliance/remote execution. Next: controlled device lifecycle and provider/enrollment binding, organizational scopes and connected blueprint/app/license/JML workflows. Unowned historical devices, cross-database user retirement, delegated device duties, delivery/retention and production operations remain explicit open work, not implicit grants.

The identity module should provide Entra-like identity and access capabilities. Identity lifecycle, application access, device trust, privileged access, and license distribution must share a consistent authorization model. License administrators should not need global administration rights.

The staged plan and acceptance criteria are in [Identity Governance](docs/features/identity-governance.md).

1. **Authorization foundation:** default-deny permissions on each service, trusted actor identity, delegated roles, independent approval, issuer/audience validation, and tenant/resource boundaries.
2. **Identity and application access:** consistent users/groups/service principals, SSO/MFA, app roles and consent, scoped delegation, and joiner/mover/leaver workflows.
3. **Effective privileged access:** connect PIM grants to runtime authorization, expire and revoke privileges reliably, and implement access reviews with durable audit evidence.
4. **Reliable license distribution:** transactional capacity checks, group-based entitlement reconciliation, license recovery on offboarding/expiry, and reports for unused seats and renewal costs.
5. **Provider integrations:** Microsoft 365/Graph and other software vendors through explicit connectors with narrowly scoped credentials, reconciliation, and visible provisioning failures.

**Implemented first increment:** `/api/licenses` now distinguishes catalog management, assignment, and approval permissions; self-service uses the authenticated account; request lists are ownership-filtered; requesters and user beneficiaries cannot review their own requests. The license kiosk uses server-reported capabilities. Database outages return `503` unless development demo fallback was explicitly enabled; production always disables fallback.

**Implemented issuer increment:** OAuth scope requests are checked against administrator-configured application grants. Browser/device sign-in fails closed on authentication outages or incomplete MFA. Verified user roles reach authorized applications through the `roles` scope; request bodies cannot invent those roles. Refresh/device credentials are bound to their original clients, refresh scopes cannot expand, public browser applications require S256 PKCE, and ID tokens cannot authorize issuer management operations. Client grant changes are persisted before cache updates and loaded at startup. Live role revocation, shared refresh-session state, consistent resource audiences, and distributed cache invalidation remain outstanding.

**Implemented license lifecycle increment:** allocation, request decisions, counters, and audit events commit atomically under PostgreSQL locks. Retries do not duplicate consumption; expiry returns capacity. Local offboarding revokes direct user assignments, cancels pending requests, and blocks new allocations until separately authorized reactivation. Quick-actions delegates the verified operator token for license release and reports partial failures. A lifecycle worker retries received offboarding events and sweeps expiry. Seventeen real PostgreSQL integration tests cover concurrency, rollback, offboarding races, and capacity guards; a dedicated CI job runs them.

**Implemented delegated quick-actions increment:** all registered business routes now use a default-deny operation registry. Application management, consent, user lifecycle, privileged role assignment, device enrollment/wipe, policy deployment, compliance reads, and infrastructure status have separate permissions. Delegated consent cannot exceed the operator's held permissions. Onboarding is constrained to approved department groups unless group assignment is explicitly authorized. Principal reads do not expose stored credentials. UI actions and dialogs consume server-reported capabilities; new applications default to no permission grants. Actual signed-token checks run against a local JWKS endpoint in addition to route and UI tests.

**Implemented authoritative group source:** identity-service now uses delegated operation permissions and requires persistent storage by default. A narrow license-group snapshot API returns canonical active IDs, inactive/unresolved references, consistent string revisions, and durable deletion tombstones. Database triggers maintain revisions, reject new dangling memberships, clean up deleted users, and atomically record actor-attributed audit/pending outbox entries. Membership removal and metadata updates are persisted. PostgreSQL concurrency and signed-HTTP tests gate this source. Outbox delivery remains outstanding.

**Implemented group license allocation:** direct/group assignment sources now share one effective seat per canonical user ID. Reconciliation preserves overlapping grants, releases departed members even when new additions lack capacity, rejects stale/unresolved snapshots, honors expiry and offboarding, and reports blocked/error states. Group review uses an explicit audited issuer/subject link, not guessed ID equivalence; beneficiaries and unmapped/disabled reviewers cannot approve or deny. The kiosk exposes group status and authorized reconcile/revoke controls. Polling requires a narrowly granted read JWT; automatic token refresh, nested/dynamic groups, and event dispatch remain outstanding.

**Implemented canonical license identities:** every private policy-service license operation now resolves the verified issuer/subject through an explicit persistent directory link. Missing/disabled links and source failures fail closed, including in demo mode. Self-service, ownership, direct/group review, actor audit, and offboarding use the same canonical user UUID; aliases cannot bypass independent review. Legacy requests remain visible to administrators but require recreation, not guessed provenance. The kiosk explains binding failures and disables actions. Bootstrap still requires authorized link administration; automatic linking/global provider mapping is not implemented.

**Implemented authoritative license recipients:** direct grants/requests/review and local activation now validate actual directory users with narrow self/eligibility reads. Versioned disabled/deleted snapshots release all local user sources and cancel pending requests atomically; stale positives cannot regrant and stale negatives cannot undo a newer confirmed state. Local offboarding remains independently controlled. The UI exposes state/errors and manual reconciliation. A separate narrow JWT enables bounded, rotating background reconciliation; expired credentials never escalate. Source transactions add audited versions and pending outbox records, not event delivery or instantaneous cross-database revocation. Current gates pass 360 policy and 91 identity unit/API tests, 66 license and 25 identity PostgreSQL tests, 395 frontend tests, and 162 gateway tests; 18 unrelated frontend TypeScript diagnostics remain.

**Implemented one license authority:** the old `license-management` entry point is now a bounded, non-caching adapter using original operator credentials and the canonical policy-service workflow. It cannot independently allocate, consume lifecycle events, spoof actors, store keys, or broadcast legacy license objects. Supported old prefixes require canonical JSON; unsupported prototype operations/WS explicitly retire rather than fake success. Canonical and adapter gateway routes preserve distinct ports/paths without registry overwrite; Next.js has no generic-backend fallback. Optional Compose profiles and a pinned install-validated adapter manifest support explicit rollout, not automatic old-data migration. Current gates pass 32 adapter tests, 361 policy and 92 identity unit/API tests, 74 license and 25 identity PostgreSQL tests, 163 gateway tests and 396 frontend tests; 18 unrelated TypeScript diagnostics remain.

**Implemented verified core-gateway boundary:** protected requests now verify RS256, issuer, explicit API audience, required claims, and access purpose without shared-key/cookie/query/cache fallback. Narrow control-plane roles guard both key aliases, module configuration, status and webhook administration; local gateway administration is not global downstream administration. Old keys are retired; metadata needs persistent storage. Native WebSocket upgrades are authenticated before opening, with expiry enforcement, not an unrestricted browser/license feed. The real gateway → canonical adapter/policy → identity PostgreSQL chain catches consumed proxy POST bodies and preserves operator authorization. Issuer access tokens separate API audience from issuing-client ownership; ID tokens stay client-specific. The integration UI follows verified capabilities. Current targeted gates: 65 gateway, 173 issuer, 361 policy, 92 identity, 32 adapter, 401 frontend, 80 license PostgreSQL and 25 identity PostgreSQL tests. Type-check still has 18 unrelated diagnostics. Lite trusts the same issuer for protected identity/license paths but needs a separately deployed core gateway for integration administration; its legacy platform gateway is not equivalent.

**Implemented durable individual-token revocation:** issuer revocations now persist as hashes with actual expiry in PostgreSQL, without Redis/memory fallback or success on failed storage. Core gateway, identity-service and policy-service check a fixed, bounded live authority after local JWT verification on every protected request, including direct API access. Idle native WebSockets also close on revocation/outage. Actual issuer → gateway/direct identity/policy → license SQL tests prove that a revoked operator cannot perform subsequent assignments. The former redirect-only logout is retired and no longer advertised as session invalidation. Shared-source build contexts and copied issuer migrations support packaging, not a verified deployment. Latest targeted gates pass 180 issuer, 90 gateway, 361 policy, 92 identity, 32 adapter and 401 frontend tests, plus 80 license, 25 identity and 10 revocation PostgreSQL tests (1,271 total); 18 unrelated frontend TypeScript diagnostics remain. See the [eleventh increment](docs/features/identity-governance.md#eleventh-implemented-increment-durable-live-token-revocation).

**Implemented persistent session families:** hashed refresh credentials, absolute authentication/expiry binding and append-only session audit now share transactional PostgreSQL state. Atomic rotation/reuse detection, owner-scoped self-service and narrowly delegated session administration revoke siblings at the live gateway/direct identity/policy boundaries. Audit failure rolls back rotation/bulk termination; SQL guards prevent identity/lifetime changes or reactivation. A fresh issuer process redeems an existing family without a token map, but keys are still ephemeral and full browser/HA continuity is not claimed. The existing PostgreSQL gate now has 21 token/session tests; latest targeted gates total 1,290 passing tests (188 issuer, 90 gateway, 361 policy, 92 identity, 32 adapter, 401 frontend, 80 license PostgreSQL, 25 identity PostgreSQL, 21 token/session PostgreSQL). The 18 unrelated TypeScript diagnostics remain. See the [twelfth increment](docs/features/identity-governance.md#twelfth-implemented-increment-persistent-session-families).

**Implemented protected persistent OAuth signing:** normal startup requires pre-provisioned owner-protected key files, with no invalid-file fallback and no production ephemeral mode. Stable public thumbprint IDs, public-only overlap, bounded trust metadata and a nonoverwriting offline helper support restart/rotation. Both Compose variants use issuer-only read-only mounts and configurable nonroot ownership; secret provisioning and the existing Helm topology still need target-host validation. Actual fresh-process tests preserve old access/refresh, switch signers with overlap, and deny removed keys despite a receiver's old public cache. Latest targeted gates: 216 issuer, 90 gateway, 361 policy, 92 identity, 32 adapter, 401 frontend, 80 license PostgreSQL, 25 identity PostgreSQL and 23 token/session/key PostgreSQL tests (1,320 total). The 18 unrelated TypeScript diagnostics remain. See the [thirteenth increment](docs/features/identity-governance.md#thirteenth-implemented-increment-protected-persistent-signing-keys).

**Implemented confidential browser mediation:** Next.js exchanges authorization codes and rotates refresh credentials server-side with a protected confidential-client secret. S256, sealed state/nonce, verified issuer/audiences/purpose/family binding and live authority checks replace the old localStorage login bypass. Only access tokens enter JavaScript memory; refresh remains in an authenticated-encrypted HttpOnly cookie. Web Locks coordinate tabs, mutations are not automatically replayed, and logout requires real family revocation. Explicit file/UID/client provisioning is mandatory. Actual Chrome/Next/issuer/PostgreSQL tests use an isolated credential fixture, not a deployed authentication-service. The browser session-administration UI, federated logout and complete HA remain open. See the [fourteenth increment](docs/features/identity-governance.md#fourteenth-implemented-increment-confidential-browser-token-mediation) for setup, evidence and limits.

**Implemented live directory authorization fences:** canonical disable/delete/unlink and a narrow manual security reset invalidate human access/refresh and pending code/device grants at the issuer, core gateway and direct identity/policy boundaries. Fresh per-request state and durable user/link generations prevent reactivation/relink from reviving old grants. A signed 30-second, read-only workload assertion with a separate audience/type/purpose breaks the introspection cycle; it is not an administrative bearer bypass. Existing human principals must be explicitly linked and reauthenticate. A real browser/database test verifies disable/sign-out/nonresurrection. User-management UI routing and independent password/role/PIM writes still need consolidation. See the [fifteenth increment](docs/features/identity-governance.md#fifteenth-implemented-increment-live-directory-authorization-fences).

**Implemented canonical user console:** browser user/group routes now reach identity-service, with capability-based reads and separate create/profile/status/reset/delete controls. Sample administrators, fabricated MFA/status and success-only actions are removed. Directory creation starts disabled and does not invent credentials or identity links. Mandatory exact record versions, row-locked field-specific writes and transactional audit prevent lost updates and stale profile re-enable. Actual browser tests verify operator/victim sessions, audit, denial and legacy-backend nonuse. See the [sixteenth increment](docs/features/identity-governance.md#sixteenth-implemented-increment-canonical-user-console-and-conditional-writes) for breaking API contracts and evidence.

**Implemented canonical runtime roles:** human OIDC roles now come from persistent canonical grants, not credential-service administrator claims. Separate role readers/managers, canonical self-administration denial, protected global delegation, bounded lifetimes, immutable grants and atomic audit support least privilege. Fresh source fingerprints enforce expiry/revoke at gateway/direct identity/policy, refresh and pending grants without worker timing; later grants cannot revive old sessions. The real role console replaces sample roles and uses known UUIDs without profile-list authority. Migration 007, reviewed offline bootstrap and reauthentication are mandatory. PIM eligibility/approval and scoped/custom roles are not included. See the [seventeenth increment](docs/features/identity-governance.md#seventeenth-implemented-increment-canonical-expiring-runtime-roles).

**Implemented canonical eligible activation:** PIM eligibility, independent review and owner activation now create a bounded lease in the same live canonical role authority. Eligibility alone/approval alone grant no license privilege. Protected PIM staff roles separate management/review from profile and active-role writes, and canonical beneficiaries cannot self-approve. Fresh authentication, requester/reviewer generation/link/role checks, atomic audit, immutable origin and transactional withdrawal fence stale or revoked approvals and actual grants. The real main PIM console replaces unrelated active labels and tests real owner reauthentication and license access. Direct active grants remain a separate authorized path; verified MFA, mandatory-PIM and tenant policy remain open. See the [eighteenth increment](docs/features/identity-governance.md#eighteenth-implemented-increment-eligible-roles-independent-review-and-real-activation).

**Implemented live actor-preserving orchestration:** quick-actions now validates access-token purpose/audience and live issuer/session/canonical state on entry and before each outbound step. All private service calls retain the verified operator and one server-created operation ID; implicit service credentials and `svc-` bypasses are retired. Authorization failure latches, caller closure aborts delegation, and credential disclosure requires one final live check. Partial/unknown application creation no longer displays success or invites blind resubmission. Actual issuer/PostgreSQL and Chrome/Next tests use recording HTTP receivers. The optional Compose profile/module is off by default; real legacy receiver authorization, durable operation reconciliation and canonical application provisioning remain open. See the [nineteenth increment](docs/features/identity-governance.md#nineteenth-implemented-increment-live-actor-preserving-orchestration).

**Implemented canonical live OAuth applications:** registration, enablement, metadata, secret rotation and soft deletion now use PostgreSQL state and verified actor audit, not a process-local registry or unversioned plaintext upsert. Application readers/managers need no global/user-directory access; privileged role/administrative scopes remain globally protected. Conditional versions, one-time generated secret disclosure and live client generations fence both human and workload tokens, refresh and pending sign-ins across issuer processes and integrated resource boundaries. The real OAuth console replaces its demo entries/actions. Migration 007, reauthentication and reviewed bootstrap/legacy-secret rotation are required. See the [twentieth increment](docs/features/identity-governance.md#twentieth-implemented-increment-canonical-live-oauth-applications).

**Implemented mandatory application access:** human OAuth login now needs an explicit active canonical user/group lease; an administrator role alone cannot bypass it. Separate access readers/managers use known client/target UUIDs without secret, registration-write or directory-profile permissions. Immutable expiring grants, actor-bound retry UUIDs, atomic source audit and membership incarnations fence access/refresh and pending login/device checkpoints without a worker. The actual console and protected offline recovery command are covered by real browser/database/HTTP tests. Identity migration 009, OAuth migration 008 and reviewed bootstrap are breaking requirements; existing users are not automatically assigned. See the [twenty-first increment](docs/features/identity-governance.md#twenty-first-implemented-increment-mandatory-user-and-group-application-access).

**Implemented verified MFA and factor-backed PIM:** the issuer verifies its own persistent canonical TOTP factor rather than trusting a credential-provider flag or process-local secret map. Real own-account enrollment/disablement requires password rechecks; pending setup is session-bound, proof requires an unused code, and factor changes fence access/refresh/pending grants. Atomic counters, durable throttling, protected purpose-bound encryption and live factor revisions work across issuer instances. PIM activation now requires a verified password-plus-code login no older than five minutes; refresh cannot renew that proof. OAuth migration 009, a distinct protected persistent MFA key and reauthentication are breaking requirements. See the [twenty-second increment](docs/features/identity-governance.md#twenty-second-implemented-increment-verified-mfa-and-factor-backed-pim).

**Implemented purpose-limited owner MFA recovery:** verified owners can explicitly generate eight single-use hashed backups with password plus an unused TOTP. Password and a backup authorize only an expiring new-authenticator setup; neither recovery step creates an application session, role, PIM lease or license right. Proven replacement atomically consumes the challenge and advances the live factor incarnation, fencing old strong tokens/refresh and pending sign-ins. Real own-account and signed-out browser flows, immutable evidence and audit rollback are tested. Fixed native token-mediator handlers prevent routing through the legacy auth service, and bounded signed-source admission is separate from public API quotas. OAuth migration 010 is required. See the [twenty-third increment](docs/features/identity-governance.md#twenty-third-implemented-increment-purpose-limited-owner-mfa-recovery).

**Implemented application MFA/age policies and purpose-limited first binding:** a separate protected authentication-policy duty configures mandatory canonical MFA and original login age, with fresh MFA, exact client versions, reasons and atomic audit. Current policy/generation is enforced at login, device approval/redemption, refresh and integrated live receivers; refresh cannot rejuvenate its proof. Assigned users can register only their initial canonical MFA factor through an expiring signed-out bootstrap, not obtain provisional administration or bypass an existing factor. The real policy console, independent duties, actual browser bootstrap and receiver/SQL negative cases are tested. OAuth migration 011 and coordinated issuer/directory/web changes are required. This is opt-in per-app enforcement, not automatic role-/resource-/tenant-wide security defaults. See the [twenty-fourth increment](docs/features/identity-governance.md#twenty-fourth-implemented-increment-application-mfa-and-authentication-age-policies).

**Implemented client-independent role authentication:** canonical role policies require real MFA and bounded original authentication age across all integrated clients/receivers, not just applications that opted in. Every live held role participates even when token role claims are omitted. Policy versions fence sessions, refresh and pending grants irreversibly; real license allocation rejects weaker alternate-client credentials. Separate protected policy duties, fixed fresh MFA for policy administrators, exact versions, reasons, atomic evidence and actor rechecks after real SQL lock waits govern changes. The role console needs no profile/assignment reads, and public first binding supports role-required MFA without provisional sessions. Identity migration 010, coordinated images and human reauthentication are required. Other role rules remain reviewed opt-in, not automatic global security defaults. See the [twenty-fifth increment](docs/features/identity-governance.md#twenty-fifth-implemented-increment-client-independent-role-authentication).

**Implemented durable Microsoft license fulfillment:** effective local user assignments now create transactional, versioned provider work for explicit immutable tenant/user/SKU mappings. A separate file-credentialed worker uses only a narrowly registered eligibility-read workload and an independently constrained database role; it cannot create local rights or retarget mappings. Fixed Graph paths, current canonical eligibility/incarnation checks, independent observed confirmation, serialized targets, connector-wide throttling, irreversible intent/audit evidence and reviewed adoption/uncertainty cleanup replace blind forwarding/retry. Protected configuration/adoption and retry duties remain distinct from ordinary license administration. The real license console shows local versus observed external state and never treats a queued decision as provisioned. Both Compose worker profiles are off by default. Policy migration 009, identity migration 011 and coordinated images are required. Provider calls are tested against owned HTTP contract fixtures; no live Microsoft tenant, consent, purchase or deployment is exercised. See the [twenty-sixth increment](docs/features/identity-governance.md#twenty-sixth-implemented-increment-durable-microsoft-license-fulfillment).

**Implemented mandatory privileged activation:** versioned canonical role policies can forbid direct grants, including global/offline bootstrap, and bound real approved PIM leases. Immutable assignment/request policy origins and live effective-role fingerprints prevent earlier grants, approvals, tokens and pending sign-ins from reviving after edits or relaxation. Separate protected policy duties have no implicit assignment, eligibility, review or license rights. Global administration can require PIM through explicitly named independent, currently authorized fresh-MFA reviewers and a preexisting eligible activation path. The actual PIM console requires exact versions, reasons and explicit invalidation acknowledgement; direct role controls honor the rule. Identity migration 012 and coordinated images/reauthentication are required. Default enforcement, scoped roles, access reviews and full legacy consolidation remain open. See the [twenty-seventh increment](docs/features/identity-governance.md#twenty-seventh-implemented-increment-mandatory-privileged-activation-policies).

**Implemented recurring independent role access reviews:** known-role policies govern current/future canonical active grants and PIM eligibilities with immutable target leases, explicit named fresh-MFA reviewers and no self/global-admin bypass. The live role authority enforces unanswered cutoffs without a privileged scheduler; retention advances only the review cycle, while denial changes actual canonical grants and eligibility-derived activations. Retirement/replacement cannot revive expired grants, and decisions fence both lease and policy versions. The real Roles console separates configuration, assigned voting and known-ID reading without directory profiles. Identity migration 013 and coordinated images are required. This governs license-administrator authority, not recipient seats. App/group/tenant reviews, notifications and complete legacy consolidation remain open. See the [twenty-eighth increment](docs/features/identity-governance.md#twenty-eighth-implemented-increment-recurring-independent-role-access-reviews).

**Implemented versioned license-source lineage:** policy migration 010 binds direct grants and whole group rules to immutable UUID incarnations with append-only source-derived versions. Conditional withdrawal requires an exact grant ETag, explicit reason and fresh real MFA; it preserves overlapping sources, capacity and transactional provider work. The kiosk uses this path for group withdrawal. Legacy grants are observed, not retroactively approved; inconsistent group data fails migration rather than being silently blessed. Remaining unconditional clients and device/application/tenant review scopes still require migration; recurring human-source reviews are implemented below. See the [twenty-ninth increment](docs/features/identity-governance.md#twenty-ninth-implemented-increment-versioned-license-source-lineage-and-conditional-withdrawal).

**Implemented recurring independent license-source reviews:** pool-specific policies enroll current/future direct grants and whole group incarnations, with separate configuration/voting/read duties and fixed fresh MFA for writers. Base expiry and direct-source eligibility origin remain immutable; unanswered cutoffs constrain the actual projection, capacity checks and provider desired-state checks. Timely retention advances only a cycle; denial disables a whole group parent rather than deleting a recreatable child. Retirement/replacement preserve existing deadlines, and decisions bind lease, policy and source versions. SQL pool gates serialize configuration with source mutations. Policy migration 011 and identity migration 014 require coordinated images; no production migration is run here. Default enforcement, device/application/group-membership reviews, tenant/resource scopes, notifications and live vendor acceptance remain outstanding. See the [thirtieth increment](docs/features/identity-governance.md#thirtieth-implemented-increment-recurring-independent-license-source-reviews).

**Implemented resource-scoped license administration:** protected pool configurators delegate only an explicit human license pool, duty and bounded lifetime to a separately authorized canonical delegate. Reader, allocator and approver duties use a distinct API and cannot extend legacy global permissions. Immutable role-source and lifecycle origins prevent authority from reviving after role replacement or reactivation; exact captured leases, model/SQL resource guards, independent approval checks and transactional use evidence fence operations through commit. The actual kiosk separates control-plane metadata from scoped pool actions. Policy migration 012, identity migration 015 and coordinated images are required. This is resource delegation within the global directory, not tenant isolation, scoped PIM or recurring delegation reviews. See the [thirty-first increment](docs/features/identity-governance.md#thirty-first-implemented-increment-resource-scoped-license-administration).

**Implemented independently approved pool-scoped activation:** immutable, bounded eligibility is separate from an activation request, its named independent fresh-MFA review and the holder's explicit fresh-MFA activation. The new protected activation-reviewer duty is not inherited merely from global administration and has no allocation powers. Approval captures the reviewer's actual canonical role/lifecycle incarnation and cannot revive after reviewer replacement or missed disable/reactivate. Actual scoped authority checks the eligibility parent and bounded lease; revocation/deactivation never claims recipient-license removal. Exact versions, original-issuer rechecks, append-only atomic evidence and a real three-actor kiosk flow are verified. Policy migration 013 and identity migration 016 require coordinated images. Standing resource/global grants remain separate; mandatory pool PIM policies, delegation access reviews and tenant isolation remain open. See the [thirty-second increment](docs/features/identity-governance.md#thirty-second-implemented-increment-independently-approved-pool-scoped-activation).

**Implemented mandatory pool activation policies:** separate protected policy administrators require fresh MFA, exact versions, explicit invalidation acknowledgement and a live independently configured activation path. Policy generations fence prior standing/PIM grants and pending/approved requests irreversibly; selected eligibilities are explicitly adopted only for future newly reviewed requests, not rewritten or retroactively approved. SQL/model gates protect global, scoped and compatibility mutations; allocator requirements also demand genuine scoped approval for request decisions and suppress auto-approval. Existing canonical group derivation, source-review withdrawals, expiry and security offboarding remain independent. Reader rules govern delegated readers, not global catalog confidentiality. Policy migration 014 and identity migration 017 require coordinated images. See the [thirty-third increment](docs/features/identity-governance.md#thirty-third-implemented-increment-versioned-mandatory-pool-activation-policies).

**Implemented recurring delegation and eligibility reviews:** independent, named fresh-MFA voters recertify exact pool grant/eligibility incarnations, separately from their configurators and original PIM activation reviewers. Immediate first-response deadlines and recurring cycles constrain actual authority without a privileged scheduler. Conditional denial revokes the administrative parent/target but preserves business licenses; retention cannot extend raw expiry or previously issued activations. Immutable parent fences and captured review generations prevent saved approvals, retirement and replacement from resetting accepted cutoffs. The kiosk offers own deadlines, assigned decisions and known-ID metadata readers without allocation privileges. Policy migration 015 and identity migration 018 require coordinated images. Native service migration replay is serialized and transactional, including rollback of partially replaced authority helpers. See the [thirty-fourth increment](docs/features/identity-governance.md#thirty-fourth-implemented-increment-recurring-delegation-and-eligibility-reviews).

**Implemented independent and recurring group memberships:** governed flat groups require an independent first approval before a new membership can enter canonical app or license-group sources. Separate protected fresh-MFA configuration/voting duties exclude holders, original grantors, policy authors and configured group members. First cutoffs govern existing links; unproven historical origins cannot be positively recertified without explicit reissue. Timely retention advances only the cycle, denial deletes the exact link, and retirement/replacement cannot reset a previous UUID or reopen unreviewed admission. The real group-source snapshot serializes cutoff materialization with group mutation and publishes a matching newer revision, avoiding same-version content conflicts. Actual issuer and real Chrome cases verify first approval, session loss, source changes and license reconciliation. Identity migration 019 and coordinated images are required. See the [thirty-fifth increment](docs/features/identity-governance.md#thirty-fifth-implemented-increment-independent-and-recurring-group-memberships).

**Implemented outage-bounded group license leases:** strict canonical v2 observations cap actual group-derived local seats at five minutes or an earlier membership/source-review/base deadline, regardless of directory-poll or housekeeping success. Separate per-member proof/audit preserves business grant identity and direct overlaps; stale evidence cannot renew rights. Actual original-bearer rechecks and deferred commit guards fence lock/DML races. The kiosk displays proof horizons and unobserved/stale states. Identity migration 020 and policy migration 016 intentionally remove unproven legacy group projections until fresh reconciliation; rollout needs coordinated protocol images and timely source credentials. Graph removal remains separately configured and observed. See the [thirty-sixth increment](docs/features/identity-governance.md#thirty-sixth-implemented-increment-outage-bounded-group-license-leases).

**Next resource-governance priorities:** extend canonical tenant/resource boundaries across issuer, directory and remaining receivers; add meaningful operator evidence/notifications, automatic credential renewal and bounded outage behavior for remaining access planes. Pool-PIM, administrative reviews and flat membership governance remain deliberate opt-in, not universal defaults or emergency-access design. General group/device/app ownership reviews and nested/dynamic membership remain outstanding. Do not present tenant metadata, a hidden menu or a scoped role label as isolation.

**Tenant migration dependency plan:** the current issuer resolves canonical subjects globally, directory queries have no tenant boundary, and license pools are globally addressed. Provider `tenant_id` is a Microsoft connector identifier, not an OpenDirectory security boundary. A real multi-organization migration must bind clients and canonical links to an authoritative tenant, carry that immutable context through grants/sessions/MFA/live checks, isolate directory and license storage with enforced cross-resource ownership, restrict administrative/background duties, and verify actual two-tenant APIs and browser flows. Existing records need an explicitly acknowledged destination; missing context must never select a permissive default. Keep new tenants unavailable until all relevant receiving paths enforce the same boundary. The single- versus multi-organization installation preference is being clarified; neither schema labels nor UI filtering prove isolation.

**Implemented scoped source automation:** dedicated client-credentials group readers now need explicit expiring canonical group/client-generation consent, with fresh protected-duty confirmation, conditional creation/withdrawal and immutable transition evidence. An owner-only source file enables automatic access-token acquisition/renewal and optionally a separate minimal user-eligibility credential. Source expiry caps the physical projection; outages, rotation and stopped providers cannot fall back to a human bearer or silently extend consent. The kiosk supports exact confirmation and metadata reading without secrets or allocation rights. Identity migration 021, policy migration 017 and coordinated v3 images are required. Secret rotation, consent renewal and tenant migration are not automated or substituted. See the [thirty-seventh increment](docs/features/identity-governance.md#thirty-seventh-implemented-increment-scoped-workload-source-consents-and-automatic-tokens).

**Still outstanding:** other receiving services do not yet consistently enforce these permissions or live revocation. Canonical user/role/PIM/client/application-assignment/MFA sources, main governance/OAuth consoles, human OIDC role sourcing and live delegated quick-actions are implemented, but independent credential/provisioning/password propagation, legacy non-OIDC/PIM/application/MFA backends, federated logout and browser session administration remain incomplete. Protected key/configuration files are not automatic secret provisioning, certificate/KMS/HSM custody, automated encryption-key rotation or complete provider HA. Independently reviewed lost-all-factors recovery, recovery notification/outbox delivery, phishing-resistant/preverified initial assurance, global enrollment and privileged-role/application security defaults, general scoped/custom roles and resource/tenant/device/risk/location policy, standard reauthentication challenges, general delegation/application/group/device reviews beyond the canonical planes above, application ownership, independent app consent/reviews and app roles, nested/dynamic app groups, expiring/asymmetric application credentials, canonical general group claims, browser realtime tickets, general workload permission issuance beyond the explicit eligibility-read bridge, signed broker/event delivery, prototype data migration, global/versioned identity lifecycle mapping and off-host audit retention remain planned. Microsoft test-tenant acceptance, purchased-SKU/capacity and service-level provisioning checks, national clouds, provider-account lifecycle and additional vendors remain required. An unsigned test webhook is not an event subscription; a local assignment alone is not vendor fulfillment. Configuration validation and owned-provider fixtures are not a deployment or Microsoft acceptance test.

**Implemented default-deny policy operations:** the direct policy receiver no longer equates human sign-in with policy authority. Canonical readers, protected configuration administrators and deployment operators have distinct permissions, and every configuration/deployment mutation needs real MFA within five minutes. The gateway and Next.js preserve the actual policy namespace/port. The main policy console replaces sample/local-success behavior with persistent canonical reads and acknowledged writes. GPO/blueprint dispatch retains the original actor, rechecks live authority around each bounded HTTP call, and uses only a narrow device `update_policy` purpose rather than an ambient internal credential. Queue acceptance is not device enforcement; unsupported targets and uncertain partial effects are explicit. Identity migration 022 and coordinated images are required. Tenant/resource isolation, independently approved versioned publication, complete commit-time policy mutation fencing, durable delivery recovery and legacy storage/UI consolidation remain open. See the [thirty-eighth increment](docs/features/identity-governance.md#thirty-eighth-implemented-increment-default-deny-policy-operations-and-actor-preserving-delivery).

**Implemented conditional, persistent policy configuration:** canonical policy, GPO, ring and blueprint changes now require exact parent versions, fresh original authority and acknowledged reasons. SQL-derived audit/origins/pending outbox commit atomically; source loss after lock/DML and known token/MFA commit cutoffs roll back rather than acknowledge a change. Blueprint child/target transitions advance their parent, preventing a saved configuration from silently adopting newer content. Mutable memory fallbacks, seeded operational GPO/ring counts and precommit policy-change emission are removed. The main GPO alias and blueprint UI use real conditional contracts; protocol-v2 capabilities fence older receivers before writes. Policy migration 018 is required. Next priorities remain canonical tenant/resource isolation and least-privilege publication/receiving-device governance, not another independent policy or licensing store. Durable event delivery, independently approved publication, receiver-bound content proof, endpoint observation and off-host evidence remain outstanding. See the [thirty-ninth increment](docs/features/identity-governance.md#thirty-ninth-implemented-increment-conditional-policy-configuration-and-atomic-evidence).

**Implemented independent policy publication:** canonical activation and managed GPO/blueprint dispatch now need a named, bounded, exact-content-and-target approval. A separate protected fresh-MFA reviewer cannot configure, deploy or allocate licenses; no author, target contributor, requester or administrator without that explicit duty can substitute for independent approval. Current requester/reviewer user, security, link and role incarnations are checked before/after approval DML and again at activation/each managed HTTP step. SQL enforces conditional one-way decisions, mandatory audit/pending outbox, known deadlines, one live request/approval per content generation and draft invalidation on edits. Main consoles implement actual request, vote, withdrawal and captured approval selection; protocol v3 rejects older receivers before privileged writes. Identity migration 023 and policy migration 019 are breaking rollout requirements, not an automatic reviewer grant. Next priorities are canonical tenant/resource isolation and receiver-bound approved content across remaining direct/internal device paths, followed by durable delivery/recovery and observed enforcement. Existing accepted device effects, runtime policy labels, outbox publication and off-host evidence are not supplied by an approval record. See the [fortieth increment](docs/features/identity-governance.md#fortieth-implemented-increment-independent-content-bound-policy-publication).

**Implemented receiving-device policy admission:** canonical `update_policy` reception now requires an original canonical fresh-MFA deployer, exact resource/publication/item references and independently derived approved settings for one persistent device/platform. A strict read-only receiver handshake prevents discovering incompatibility after an old receiver has already accepted a command. Raw global-administrator payloads and ambient internal/workload bypasses are rejected. Commands, captured operation origin, immutable audit and pending outbox commit together, including post-lock/post-DML source checks and known lease/credential commit cutoffs. Same captured-operation retries reuse acceptance without adopting a new actor/content or extending the delivery horizon. Generation-bound devices pull actual stored offers and report one terminal outcome; old unverified queues are history, not retrospectively approved work. Policy capabilities v4, issuer migration 012, a protected `OAUTH_POLICY_SOURCE_URL`, coordinated receiving images and renewed device credentials are breaking requirements. The next priorities remain tenant/resource isolation, separate effective-versus-draft publication and complete lifecycle/workload/command governance, not another permissive policy queue. Persistent workflow planning/recovery, immediate cancellation of accepted jobs, safe device execution/deduplication, other command families, enrollment bootstrap governance and off-host evidence remain required. See the [forty-first increment](docs/features/identity-governance.md#forty-first-implemented-increment-receiver-bound-policy-commands-and-durable-device-receipts).

---

**Implemented owned policy-command cancellation:** fresh canonical deployers can stop an exact own accepted command, including after its source publication is withdrawn or its device generation changes. Original receipts, captured cancellation operations and explicit reasons prevent retargeting or ambiguous duplicate acceptance. Command status, retained cancellation, derived audit and pending outbox commit atomically; current actor authority and known credential/MFA deadlines are checked through commit. Own SQL history is bounded, payload-free and separate from the legacy administrator fleet view. The main blueprint console reloads that history, confirms individual stops and distinguishes stopped future offers from previously received or executed work. Issuer migration 013 and coordinated issuer/web images are required. Next priorities still include tenant/resource isolation, automatic source-aware cancellation/supersession, incident authority over another operator's jobs, effective-versus-draft runtime and independently observed endpoint enforcement. See the [forty-second increment](docs/features/identity-governance.md#forty-second-implemented-increment-owned-policy-command-cancellation-and-recoverable-receipts).

**Implemented read-only manufacturer capacity observation:** a separately provisioned collector reads fixed Microsoft subscribed-SKU endpoints using a reviewed read-only Graph application and a connector-bound, nonadministrative PostgreSQL role. It has no user/entitlement/configuration authority. Whole successful/failed captures, audit and pending outbox commit with source/connector-generation and deadline fences; incomplete pages, outages or later failed attempts never preserve a false current inventory. The license console compares explicit mapped products and local unexpired projection rows with observed enabled/warning/suspended/locked-out and consumed units, without changing pool sizes or claiming reserved/fulfilled rights. Policy migration 020, separate protected configuration/grants and the disabled-by-default `license-capacity` profile are rollout requirements. Capacity reservations/admission at actual vendor writes, automatic reviewed commercial-pool reconciliation, billing/cost evidence, additional clouds/vendors, tenant isolation and live Microsoft acceptance remain open. See the [forty-third increment](docs/features/identity-governance.md#forty-third-implemented-increment-read-only-manufacturer-capacity-and-bounded-reconciliation).

**Implemented conservative vendor-write admission:** new Microsoft additions require a current enabled user-SKU observation and a reviewed finite source/product-generation budget. SQL serializes actual charges with write intent, derived audit and pending outbox; a short-lived one-time pre-POST receipt rechecks bindings, target state and known deadlines. Unknown attempts remain charged across fresh captures and restarts, and removals remain possible without capacity. New inventory never automatically refills the quota. Conditional rebasing requires an explicit offline schema-owner acknowledgement of external-usage/outcome review and stable durable observations; this is not an independently authenticated application-level reviewer workflow. Policy migration 021, renewed worker function grants and coordinated policy/web/worker images are required. The main console reports observed stock and local quota separately. Vendor-exclusive reservations, automated independently approved commercial-pool adjustment, actual Microsoft acceptance, tenant isolation and the SQL-to-HTTP effect gap remain open. See the [forty-fourth increment](docs/features/identity-governance.md#forty-fourth-implemented-increment-conservative-vendor-write-admission).

**Implemented canonical tenant ownership/lifecycle anchor:** identity migration 024 retains disabled-first tenant generations and explicit reviewed ownership of existing user/group/OU UUIDs, without guessing a default owner or adopting old data. Unowned/paused people lose canonical positive authorization/eligibility, and adoption/pause/re-enable fence old access, refresh and pending human code/device origins. Same-owner reference/application-target checks, atomic evidence and namespace retirement cover those paths. Positive identity-source protocol v5 and coordinated issuer/identity images intentionally reject a down-level source. **This is not complete tenant isolation:** global direct directory/policy/role administration, OAuth clients, pools/provider/device ownership, workloads, general receiver/resource scopes and tenant-bound creation/administration remain required. The next acceptance gate is consuming this ownership in canonical receiving-service authorization, not another header selector or parallel directory. See the [forty-fifth increment](docs/features/identity-governance.md#forty-fifth-implemented-increment-canonical-tenant-ownership-and-lifecycle-anchor).

## Critical — Must Fix Before Production

### 1. Resource-Scoped Authorization Across Services

- **Currently:** quick-actions has operation-level default-deny guards and bounded escalation paths; policy-service now additionally supports explicit pool-scoped licensing leases without global permission expansion; identity-service guards direct users/groups/OUs and narrow license snapshots. The directory remains global, and many other direct downstream administrative routes lack equivalent resource or tenant boundaries.
- **Required:** consistent permissions on receiving services, tenant/resource boundaries, resource audiences, live role/PIM revocation, and explicitly granted workload identities.
- **Impact:** protecting an orchestration gateway alone does not prevent bypass through an insufficiently guarded direct service API.
- **Tenant acceptance plan:** establish immutable canonical tenant ownership for subjects, groups, application assignments and pools; bind it and its generation to issuer authorization, pending grants and sessions; enforce the same boundary in direct receivers, reads, writes, joins, reconciliation and provider mappings. Header/body tenant selection or an unfiltered global administrator must not bypass it. Existing global records need an explicit reviewed adoption plan and reauthentication, not guessed ownership. Verify real separate-tenant operators through issuer, direct/gateway APIs, concurrent SQL writes and browsers before advertising isolation.

### 2. Inter-Service Authentication

- **Currently:** quick-actions forwards only the verified original operator to configured HTTP receivers, with live authorization before every step and no ambient service-token fallback. Receiver-side enforcement is still inconsistent; legacy services may reject these tokens and must be upgraded or kept unexposed rather than given a privileged compatibility bypass.
- **Required:** explicitly scoped workload identities or delegated user authorization, audience validation, and consistent permission guards on receiving services; authenticated transport where appropriate.

### 3. LAPS Password Encryption

- **Currently:** LAPS passwords stored in plain text in PostgreSQL
- **Required:** encryption at rest (AES-256-GCM, key from vault or KMS)
- BitLocker recovery keys have the same issue

### 4. Break-Glass Audit Completeness

- **Currently:** break-glass events are recorded but records are mutable
- **Required:** append-only audit log with WORM storage for break-glass records
- Compliance requirement for any PAM solution

### 5. Session Recording Storage

- **Currently:** PIM session activities stored as JSONB in PostgreSQL alongside other operational data
- **Required:** separate append-only store, retention policy, encryption at rest

---

## High Priority

### 6. Remote Command Execution UI

- **Backend:** `POST /api/remote/execute` and status polling endpoints fully implemented in device-service
- **Missing:** command console UI in DeviceDetailPanel
- **Affected users:** IT admins who need to run ad-hoc commands on managed devices

### 7. LDAP Schema Browser UI

- **Backend:** full schema management API in ldap-proxy (`GET /api/schema/object-classes`, `/attribute-types`, `/validate`)
- **Missing:** UI view for browsing and extending the AD schema
- **Affected:** directory architects adding custom attributes

### 8. Certificate Lifecycle UI

- **Backend:** `/api/certificates/*` (issue, renew, revoke) in certificate-authority service
- **Missing:** certificate management view in the frontend
- **Affected:** PKI administrators

### 9. Geofencing Configuration UI

- **Backend:** `/api/geofencing/zones` CRUD in device-service
- **Missing:** map-based or coordinate-input UI for zone management
- **Affected:** location-aware conditional access policies have no way to be configured from the UI

### 10. Password Policy Enforcer Integration

- **Backend:** `PasswordPolicyEnforcer` class exists in `authentication-service/src/policies/`
- **Missing:** not wired into the register, change-password, or reset-password flows in `index.js`
- **Impact:** password complexity rules are defined but not enforced at runtime

### 11. Threat Detection Dashboard

- **Backend:** `/api/analytics/threats`, `/api/analytics/anomalies`, `/api/analytics/predictions` in device-service
- **Missing:** threat dashboard UI
- **Affected:** security operations team has no visual surface for these signals

### 12. Backup and DR UI

- **Backend:** full `/api/backup/*` and `/api/dr/*` in device-service
- **Frontend:** `AuditView` skeleton and `BackupView` component exist but make no API calls
- **Missing:** real backup schedule display, status indicators, and restore workflow

### 13. Network Profile Deployment UI

- **Backend:** `/api/agent/network/*` (Wi-Fi, VPN, email configuration) in device-service
- **Missing:** profile builder and deployment UI
- **Affected:** administrators who need to push network configurations to managed devices

---

## Medium Priority

### 14. User Offboarding UI

- **Backend:** `POST /api/quick/users/:id/offboard` fully implemented
- **Missing:** "Offboard Employee" action in UserDetailPanel or admin view
- **Workaround:** direct API call

### 15. Bulk Enrollment UI

- **Backend:** `POST /api/quick/devices/bulk-enroll` implemented
- **Missing:** CSV import or multi-device form in the Enrollment Wizard
- **Current wizard:** handles a single device only

### 16. Policy Rollback UI

- **Backend:** `POST /api/quick/policies/deployments/:id/rollback` implemented
- **Missing:** rollback button in the deployment history view
- **Current state:** the wizard shows a `deploymentId` but provides no rollback action

### 17. PIM Multi-Approver Chain UI

- **Backend:** PIMService supports multi-level approval chains
- **Missing:** UI to configure `approvalChain` on roles; currently the UI only shows a single-approver field
- **Affected:** high-security environments that require dual or sequential approval

### 18. Kerberos Keytab Generation UI

- **Backend:** `POST /api/kerberos/keytabs/:name` in kerberos-kdc
- **Missing:** keytab download UI for service account setup
- **Workaround:** direct API call

### 19. Multi-Tenant Support

- `services/enterprise/multi-tenant/` directory exists with initial scaffolding
- Canonical identity migrations 024/025 provide explicitly reviewed immutable user/group/OU ownership, parent lifecycle revocation, original-token tenant proofs and same-tenant subject-link administration with retained subject ownership. Ordinary directory GET collections/details/search and user role history now use that original tenant in actual SQL and recheck authority before releasing results.
- Ordinary directory reads/writes, roles/PIM/policies, OAuth clients, devices, licensing resources and other receivers still lack complete tenant scopes; this is not isolated shared-customer hosting.
- Migration 026 and the canonical POST receiver now derive new user/group/OU ownership from the verified original actor, including atomic evidence, disabled-first/empty defaults, scoped OU parents and original/deferred authority fences. The main user console negotiates creation protocol 1; no default tenant or automatic adoption of old resources is supplied.
- Migration 027 and the existing-user PUT/reset/DELETE receiver now bind actual locked user state and target owner to the original token, require atomic mutation evidence/outbox, preserve exact profile/delete ETags and derive legitimate own disable/reset/delete without skipping normal issuer revocation. The main user console negotiates user-mutation protocol 1; corrected gateway transport preserves directory namespaces and version headers. Full verification passes 3,963 distinct cases, including 238 native identity, 234 actual issuer and 47 actual Chrome cases; this is native/test-mode evidence, not production rollout acceptance.
- Next: bind the complete direct-role/PIM/review/authentication-policy authority lifecycle and existing OU/other resource targets to the original tenant, including post-lock/final origin checkpoints and legitimate self-revocation. Raw/historical unowned records still need explicit offline adoption; these remaining receiving planes prevent any complete directory-isolation claim.
- The authority-boundary plan is backed by a historical isolated two-tenant SQL observation: pre-032 direct-role and PIM eligibility receivers accepted a coherent foreign recipient and changed the foreign effective role source. Migration 032 now refuses those new target transitions; retained contaminated sources and global policy authority still require explicit owned publication and complete command/queue/UI changes. The original unwanted observation is not a passing isolation test, and the new target fence is not a complete authority cutover.
- Its first receiving foundation is an explicitly inactive migration-review ledger and owner-only CLI (migration 030): complete typed per-role proposals, exact owned legacy graph coverage, foreign/unknown quarantine requirements, preserved physical cutoffs, independent immutable draft/event/pending outbox confirmation and no live same-transaction effects. There is no activation endpoint or positive source protocol yet; owned source publication, all authority command receivers and the real console cutover remain required.
- Migration 031 and `OwnedAuthorityPlan` now assess a committed draft against its exact owned graph and proposed tenant/role policies, without changing the live resolver. Missing mandatory activation/review, incompatible source duration, quarantined provenance and original expiry/recurrence remain negative rather than being rebased at migration time. The owner-only `plan` command requires independent receiving evidence and reports only non-authorizing proposals; named reviewer duties, independently approved publication, the strict live source protocol and complete receiving/UI cutover are still required.
- Migration 033 persists distinct immutable **sealed** owned policy bases from a committed exact draft: tenant/namespace identities, separate MFA/PIM/review component version keys, foreign-keyed base references and mandatory owner-attributed event/pending outbox. SQL-only owner inspection has no global fallback and no public authority effect. Its migration-033 receipt covers 19 new native cases, identity 384/384, unit 508/508 and actual production-mode subset 11/11. This is not policy publication, mutable owned policy commands, role/source adoption, a new authority protocol or closure of the live global-governance gap.
- Migration 034 implements the owner-only [sealed source kernel](docs/features/identity-governance.md#implemented-sealed-source-kernel-not-live-authority): typed owned components, exact reviewed source/audit/graph bindings, complete active PIM and both review planes, original finite cutoffs and no global-positive fallback. Changed/new/quarantined sources do not silently become adopted. Its [targeted gates](docs/features/identity-governance.md#migration-034-verification) pass **508 unit, 408 native identity and 11 actual production-mode cases**, including 24 new source cases. It remains explicitly non-authorizing; the single active source/protocol, bootstrap/publisher, receiving commands and consoles still require their coordinated cutover.
- Actual role, PIM and role-MFA write handlers enforce [original-bearer command checkpoints](docs/features/identity-governance.md#implemented-original-bearer-command-checkpoints-live-partial) before storage and after SQL/audit effects, including no-op and self-change results; issuer rejection/outage rolls back. Fixed/action-specific fresh assurance is checked again after the final await. Their migration-034 [complete named regression](docs/features/identity-governance.md#complete-named-regression-for-command-checkpoints) passes **4,317** cases, including 520 identity unit, 408 native identity, 265 full signed and 50 actual Chrome cases. Actual PIM-enabled allocation and self-withdrawal preserve existing business licenses. The same 17 TypeScript diagnostics remain; owned publication/source and the complete console cutover stay open.
- Migration 035 adds [deferred local SQL checkpoints](docs/features/identity-governance.md#implemented-deferred-authority-checkpoints-migration-035) across all five role/PIM/policy/review management classes. Physical original token/MFA deadlines, exact final metadata/event/pending outbox, owner/incarnation checks and no canonical DML/truncation after sealing survive cleared scopes. The [complete named regression](docs/features/identity-governance.md#complete-named-regression-after-migration-035) passes **4,365 cases**, including 549 identity unit, 425 native identity, 267 full signed and 50 actual Chrome cases. The same 17 TypeScript diagnostics remain. This is not exact pre-admitted effect/legitimate-delta proof, a forced legacy-writer cutover, active owned authority, distributed issuer revocation serialization, vendor fulfillment or rollout approval.
- Migration 036 materializes [immutable owned initial source versions](docs/features/identity-governance.md#implemented-owned-source-bases-migration-036-not-active), independent policy references and ordered same-namespace/unresolved graph edges. Exact committed source-set/event/pending-outbox evidence is mandatory for the sealed kernel; no candidate fallback or automatic adoption is available. Private assessment schema 2 remains non-authorizing. Its [targeted 1,021-case receipt](docs/features/identity-governance.md#migration-036-verification) covers 549 identity unit, 445 native identity (20 new cases) and 27 actual signed production-mode cases, including local PIM-enabled licensing regression, not the full historical thirteen-gate set. Next: explicit current source/policy references and immutable admitted history with exact receiving transitions, then the coordinated active source/publisher/protocol/console cutover; the full platform objective stays open.
- Migration 032, `AuthorityTenant` and the actual role/PIM handlers add a defensive live target boundary while that source cutover remains incomplete: canonical actor home is resolved through the actual enabled link/tenant, users are locked only within that home, known foreign eligibility/request targets return 404, and PIM queues spend their SQL limit only on own recipients. Canonical SQL writes also reject foreign recipients/positive saved PIM lineage and foreign review voters; missing receiving guards and limited-login/SET ROLE laundering fail closed. Current global governance remains shared, imported foreign sources are not automatically revoked, and this does not supply exact receiving roots/outboxes, original-bearer post-DML checks, complete review/policy scoping or a negotiated authority-management console.
- The historical migration-032 [complete named regression](docs/features/identity-governance.md#complete-named-regression-for-the-target-fence) passes **4,248** cases: full signed issuer/receiver 251/251, native identity 365/365 and actual Chrome 50/50. The first Chrome attempt exposed an expiring previous-counter OTP in the test helper; a real-clock stale-code/fresh-confirmation/replay case and explicit response checks fix the fixture without relaxing production MFA. Existing 17 TypeScript diagnostics remain. This receipt is not extended to subsequent migrations, complete owned governance or production rollout.
- Group management now has active scoped public CRUD and a real `/usergroups` console without examples, invented types or profile-read dependencies. `GroupMutator`/migration 028 provide conditional source-incarnation-bound writes; `ScopedGroupReviews`/migration 029 scope review targets, voters, queues and decisions before the SQL limit. Both advertise separate protocol 1 only for coordinated receivers. Native tests cover rollback, bounded cutoffs, provenance and observed concurrency; actual browser CRUD and focused signed tests cover foreign denial and group-derived application self-reduction. The [implemented boundary and acceptance evidence](docs/features/identity-governance.md#fiftieth-implemented-increment-canonical-tenant-bound-group-management) records the passing 4,076-case gate and remaining platform scope; a local receipt does not prove external license delivery.
- Production HTTP transport now admits originless callers only through normal canonical bearer/live-state checks and preserves the gateway's approved browser CORS across downstream proxies. The nine native production cases pass after actual global-admin review withdrawal in a ten-case order reproduction, and 120 gateway cases pass. The first complete transport run exposed the test actors' legitimately withdrawn rights; separate canonical actors fix the fixture without weakening authorization. The corrected 249-case signed regression passes, bringing the named verified set to 4,098 distinct cases. See the [acceptance and deployment limits](docs/features/identity-governance.md#fifty-first-implemented-increment-production-gateway-transport); there is no automatic rollout or API-key fallback.
- Helm chart has no tenant isolation; all services share a single namespace

### 20. Real Samba Integration

- **Currently:** the samba-ad-dc module has placeholder implementations for several operations
- Trust creation, FSMO role transfer, and some replication operations are simulated rather than delegated to `samba-tool`
- **Required:** shell integration with `samba-tool` and `kadmin` for production use

### 21. Apple MDM (APNS) Real Integration

- **Currently:** APNS profile generation is mocked; no real push connection
- **Required:** APNS certificate provisioning, APN push implementation, and full MDM protocol handling
- **Affects:** all macOS and iOS enrollment and management flows

### 22. Windows WinRM Integration

- **Currently:** WinRM configuration is generated but never executed
- **Required:** real WinRM connection to push policy and execute remote actions on Windows machines

### 23. Linux SSSD Real Configuration

- **Currently:** an SSSD config file is generated in memory
- **Required:** a delivery mechanism (SSH, Ansible, or an on-device agent) to apply the configuration to Linux endpoints

---

## Low Priority / Nice to Have

### 24. Graph Explorer UI

- **Backend:** `services/enterprise/graph-explorer` exists with Microsoft Graph-compatible endpoints
- **Missing:** interactive query UI for exploring the graph API

### 25. Automation Rules Builder

- **Backend:** `services/enterprise/automation` exists
- **Missing:** visual rule builder in the frontend (trigger → condition → action)

### 26. Policy Simulator UI

- **Backend:** `services/enterprise/policy-simulator` exists
- **Missing:** "what-if" simulation UI to preview policy impact before deployment

### 27. Mobile Companion App

- No native iOS or Android companion app for device enrollment
- **Currently:** QR code points to a web-based enrollment flow

### 28. SAML IdP Integration

- SAML routes exist in enterprise-directory (`/saml/*`)
- Not tested end-to-end with a real SAML service provider

### 29. Dark Mode

- Frontend uses CSS variables throughout
- No dark mode theme is defined

### 30. Accessibility (a11y)

- Components use inline styles without ARIA attributes
- Screen reader support is not implemented

---

## Technical Debt

### Testing Gaps

- Frontend component tests: 131 tests exist but do not cover `LAPSView`, `BitLockerView`, `TrustManagementView`, `KerberosAdminView`, or `ReplicationView` (all recently added)
- Browser coverage includes five fixture-backed layout/drivers tests and four real confidential-login/PostgreSQL tests; most administrative feature flows remain uncovered.
- No load or performance tests

### Security Hardening

- Rate limiting exists on quick-actions (200 req/min) but is absent on most other services
- No WAF rules in the Helm chart Ingress
- CORS is set to `*` in several services; should be restricted to known origins
- Most service endpoints check authentication but do not enforce authorisation level (no RBAC on individual routes)

### Observability

- Prometheus metrics are emitted by all services
- No Grafana dashboards are defined in the repository
- No distributed tracing (OpenTelemetry not integrated)
- No alerting rules defined

### Infrastructure

- Helm chart: no `PodDisruptionBudget` for critical services
- No `HorizontalPodAutoscaler` configured for any service
- No Kubernetes `NetworkPolicy` resources defined (all pods can reach all pods)
- Secrets management: environment variables used directly with no Vault or external secrets integration

---

## Completed

Features fully implemented end-to-end (backend + UI + tests):

- Active Directory core (users, groups, OUs, computers) via Samba
- Kerberos principal management and delegation (S4U2Self, S4U2Proxy, RBCD)
- LDAP schema management API with RFC 4515 filter parser
- PIM: JIT access, multi-approver chains, risk scoring, break-glass activation
- PIM: session recording and session replay
- GPO enforcement engine and Resultant Set of Policy (RSoP)
- Directory audit trail (all object changes, group changes, GPO events)
- Forest and trust management API
- Computer domain join and unjoin, LAPS, and BitLocker key escrow
- Multi-DC replication monitoring
- Device management: enrollment, compliance scanning, remote actions
- Service Principal: create, list, delete, rotate (one-click from UI)
- User onboarding and offboarding orchestration
- Policy deployment with dry-run mode and rollback
- Compliance snapshot view
- Audit log view
- Apple Business Manager-style three-column UI
- 780+ automated tests (unit + integration + E2E + component)
- Kubernetes Helm chart (38 deployment templates)
- gRPC event bus with 50+ routing keys
