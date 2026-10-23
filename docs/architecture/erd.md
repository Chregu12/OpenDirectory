# ERD: tatsächlich implementiertes Organisationsprofil

Nur das persistente Teilmodell der Migrationen 037–039 und seine existierenden Tenant-/Checkpoint-/Proof-Grenzen. Nicht das vollständige künftige SaaS-Modell.

```mermaid
erDiagram
  identity_tenants ||--o| identity_organization_profiles : owns
  identity_tenants ||--o{ identity_organization_events : scopes
  identity_organization_profiles ||--o{ identity_organization_events : retains_history
  identity_organization_events ||--o| identity_organization_profiles : current_command_deferred_FK
  identity_organization_events ||--|| identity_organization_outbox : requires_at_commit
  identity_authority_command_checkpoints ||--o| identity_organization_events : same_transaction_receiving_proof

  identity_tenants {
    uuid id PK
    text display_name
    boolean enabled
    bigint version
    bigint generation
  }
  identity_organization_profiles {
    uuid id PK
    uuid tenant_id FK,UK
    bigint version
    text name
    text legal_form
    text registration_number
    text tax_id
    text address_line1
    text address_line2
    text postal_code
    text city
    text country
    text timezone
    text default_language
    text contact_email
    text contact_phone
    text website
    uuid command_id FK
    timestamptz created_at
    timestamptz updated_at
  }
  identity_organization_events {
    uuid id PK
    uuid tenant_id FK
    uuid organization_id FK
    text action
    jsonb actor
    text token_sha256
    text reason
    jsonb before_state
    jsonb after_state
    timestamptz created_at
    timestamptz valid_until
    bigint transaction_id UK
  }
  identity_organization_outbox {
    uuid id PK,FK
    uuid tenant_id FK
    text action
    text status
    timestamptz created_at
  }
  identity_authority_command_checkpoints {
    uuid id PK
    uuid tenant_id FK
    uuid user_id
    jsonb original_context
    text token_sha256
    timestamptz valid_until
    bigint transaction_id UK
  }
```

Die Checkpoint-Kante ist eine deferred geprüfte Transaktions-/Actor-/Token-Beziehung, kein deklarierter Foreign Key zwischen diesen beiden Tabellen. Die exakt eine Pending-Outbox wird zusätzlich zum FK bei Receiving/Commit verlangt. Versionen und Generationen bleiben nach aussen bigint-Strings.

## Begrenzte Profildelegation

```mermaid
erDiagram
  identity_tenants ||--o{ identity_organization_delegations : scopes
  users ||--o{ identity_organization_delegations : receives
  users ||--o{ identity_organization_delegation_events : target_FK
  identity_organization_delegation_events ||--o| identity_organization_delegations : grant_event_deferred_FK
  identity_organization_delegations ||--o| identity_organization_delegation_revocations : retained_revocation
  identity_organization_delegation_events ||--o| identity_organization_delegation_revocations : revoke_event_deferred_FK
  identity_organization_delegation_events ||--|| identity_organization_delegation_outbox : requires_at_commit
  identity_authority_command_checkpoints ||--o| identity_organization_delegation_events : same_transaction_receiving_proof

  identity_organization_delegations {
    uuid id PK,FK
    uuid tenant_id FK
    uuid user_id FK
    timestamptz expires_at
    timestamptz created_at
  }
  identity_organization_delegation_revocations {
    uuid grant_id PK,FK
    uuid event_id FK,UK
    uuid tenant_id FK
    timestamptz created_at
  }
  identity_organization_delegation_events {
    uuid id PK
    uuid tenant_id FK
    uuid user_id FK
    uuid grant_id
    text action
    timestamptz expires_at
    jsonb actor
    text token_sha256
    text reason
    timestamptz created_at
    timestamptz valid_until
    bigint user_revision
    bigint transaction_id UK
  }
  identity_organization_delegation_outbox {
    uuid id PK,FK
    uuid tenant_id FK
    text action
    text status
    timestamptz created_at
  }
```

`event.grant_id` wird durch den tatsächlichen Befehls-/Commit-Beleg an den Grant gebunden, nicht als deklarierter FK ausgegeben. Die Checkpoint-Kante ist ebenfalls eine tatsächliche deferred Receiving-Prüfung. Die User-FKs behalten das Ziel; Original-Actors sind gebundene historische JSON-Nachweise, keine erneut verwendbaren Rollen. Die Autorisierungsinvalidierung erfolgt an der vorhandenen kanonischen User-Zeile im selben Commit.

## Pending-Registrierung

```mermaid
erDiagram
  identity_tenants ||--o| identity_company_registrations : new_disabled_tenant_deferred_FK
  users ||--o| identity_company_registrations : new_disabled_candidate_deferred_FK
  identity_company_registrations ||--|| identity_company_registration_events : required_event_deferred_FK
  identity_company_registration_events ||--|| identity_company_registration_outbox : required_pending_receipt

  identity_company_registrations {
    uuid id PK
    uuid tenant_id FK,UK
    uuid user_id FK,UK
    text issuer
    text subject
    text username
    text email
    text display_name
    jsonb profile
    text payload_sha256
    uuid proof_nonce UK
    timestamptz proof_issued_at
    timestamptz proof_valid_until
    text request_sha256
    uuid event_id FK,UK
    timestamptz created_at
    bigint transaction_id UK
  }
  identity_company_registration_events {
    uuid id PK
    uuid registration_id FK,UK
    uuid tenant_id FK
    text type
    int version
    uuid correlation_id
    timestamptz created_at
    jsonb payload
    jsonb receipt
  }
  identity_company_registration_outbox {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Issuer/Subject ist zusätzlich gemeinsam eindeutig. Der private kurzlebige Issuer-Workload ist kein aktiver Human-Checkpoint oder Anwendungs-Access-Token. Seine tatsächliche noch gültige Admission bindet nur die neue deaktivierte Komponente und die ursprüngliche Commit-Frist; gespeicherte Credentials oder eine globale Adminrolle existieren in diesen Tabellen nicht. Die Correlation-ID entspricht dem unveränderlichen Request-Key.

## Interne Firmenprüfung: Migration 040

```mermaid
erDiagram
  users ||--o{ identity_company_review_operators : explicitly_appointed
  identity_tenants ||--o{ identity_company_review_operators : management_home
  identity_company_review_events ||--o| identity_company_review_operators : current_version
  identity_company_registrations ||--o| identity_company_registration_reviews : final_decision
  identity_company_review_events ||--o| identity_company_registration_reviews : decision_receipt
  identity_company_review_events ||--o{ identity_company_registration_reviews : retained_operator_source
  identity_tenants ||--o{ identity_company_review_events : event_owner
  identity_company_review_events ||--|| identity_company_review_outbox : pending_evidence
  identity_company_review_operators {
    text issuer PK
    uuid user_id PK,FK
    uuid tenant_id FK
    bigint version
    boolean enabled
    uuid command_id FK,UK
  }
  identity_company_registration_reviews {
    uuid registration_id PK,FK
    uuid id FK,UK
    text decision
    uuid operator_event_id FK
    timestamptz created_at
  }
  identity_company_review_events {
    uuid id PK
    uuid tenant_id FK
    uuid target_id
    text kind
    jsonb actor
    text reason
    jsonb before_state
    jsonb after_state
    timestamptz valid_until
    bigint transaction_id UK
  }
  identity_company_review_outbox {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Das Ereignis eines Offline-Operatorbefehls gehört zum Management-Tenant, das einer Antragsentscheidung zum Ziel-Tenant. Letzteres besitzt zusätzlich den Original-Checkpoint des Management-Tenants. `target_id` ist ein typisierter Ereignisbezug auf User oder Antrag, kein polymorpher SQL-FK; die konkreten Root-Tabellen besitzen die tatsächlichen FKs. Reguläre API-Benutzer können das Register nicht ändern und keine historischen Reviews löschen. Personenbezogene FKs und Audits benötigen weiterhin kontrollierte Retention-/Löschregeln; keine physische Sofortlöschung oder bereits fertige Compliance-Archivierung wird behauptet.

## Eigene Firmenaktivierung: Migration 041

```mermaid
erDiagram
  identity_company_registrations ||--o| identity_company_activations : own_transition
  identity_company_registration_reviews ||--o| identity_company_activations : approved_source
  identity_tenants ||--o| identity_company_activations : own_company
  users ||--o| identity_company_activations : initial_owner
  identity_organization_profiles ||--o| identity_company_activations : initial_profile
  identity_organization_events ||--o| identity_company_activations : initial_profile_receipt
  identity_company_activations ||--|| identity_company_activation_events : exact_transition
  identity_company_activation_events ||--|| identity_company_activation_outbox : pending_evidence
  identity_company_activations {
    uuid id PK
    uuid registration_id FK,UK
    uuid review_id FK,UK
    uuid tenant_id FK,UK
    uuid user_id FK,UK
    uuid profile_id FK,UK
    uuid profile_event_id FK,UK
    text console_client_id
    text issuer
    text subject
    uuid proof_nonce UK
    text request_sha256
    timestamptz created_at
    timestamptz valid_until
    bigint transaction_id UK
  }
  identity_company_activation_events {
    uuid id PK,FK
    uuid tenant_id FK
    text type
    int version
    uuid correlation_id FK
    jsonb actor
    jsonb before_state
    jsonb after_state
    timestamptz created_at
  }
  identity_company_activation_outbox {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Der Aktivierungsdatensatz ist der unveränderliche ursprüngliche Owner-Source, kein allgemeines Rollen-/Mitgliedschaftsregister. Der Profil-FK ist zusätzlich zusammengesetzt mit dem Tenant. Der Console-Client gehört zur separaten Issuer-Datenbank; es wird kein unmöglicher datenbankübergreifender FK behauptet. Die private aktuelle Owner-Abfrage prüft Bindung und Berechtigung vor der tatsächlichen Console-Nutzung. Audit-/Outbox-Retention und kontrollierte spätere Lösch-/Owner-Übertragungsprozesse bleiben erforderlich.

## Kanonische Organisationseinheiten: Migration 042

```mermaid
erDiagram
  IDENTITY_TENANTS ||--o{ IDENTITY_TENANT_OWNERSHIP : owns
  IDENTITY_TENANT_OWNERSHIP ||..o| OUS : typed_ou_namespace
  OUS o|--o{ OUS : parent_id
  IDENTITY_TENANTS ||--o{ IDENTITY_DIRECTORY_OU_CREATIONS : retains
  IDENTITY_TENANTS ||--o{ IDENTITY_DIRECTORY_OU_EVENTS : records
  IDENTITY_TENANTS ||--o{ IDENTITY_DIRECTORY_OU_OUTBOX : scopes
  OUS o|..o| IDENTITY_DIRECTORY_OU_CREATIONS : retained_creation_identifier
  OUS o|..o{ IDENTITY_DIRECTORY_OU_EVENTS : retained_target_identifier
  IDENTITY_DIRECTORY_OU_EVENTS ||--o| IDENTITY_DIRECTORY_OU_OUTBOX : pending_receipt
  OUS {
    uuid id PK
    uuid parent_id FK
    varchar name
    text description
    bigint revision
    timestamptz created_at
    timestamptz updated_at
  }
  IDENTITY_DIRECTORY_OU_CREATIONS {
    uuid ou_id PK
    uuid tenant_id FK
    jsonb proof
    timestamptz valid_until
    bigint transaction_id UK
  }
  IDENTITY_DIRECTORY_OU_EVENTS {
    uuid id PK
    uuid tenant_id FK
    uuid ou_id
    text action
    text type
    integer version
    uuid correlation_id
    jsonb actor
    jsonb proof
    jsonb before_state
    jsonb after_state
    timestamptz created_at
    timestamptz valid_until
    bigint transaction_id UK
  }
  IDENTITY_DIRECTORY_OU_OUTBOX {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Gestrichelte OU-Beziehungen sind Identifier-/Namespace-Beziehungen, keine behaupteten FKs auf eine nach Retirement noch vorhandene OU-Zeile. Der unveränderliche `resource_kind=ou`-/`resource_id`-Namespace bestimmt die tatsächliche Tenant-Hoheit. Der bestehende Parent-FK bleibt erhalten; kanonische Löschungen verweigern Kinder statt dessen Legacy-`SET NULL` als Business-Workflow zu benutzen. Die neuen Tabellen behalten ihre Tenant-FKs und eigene Outbox-/Event-FK-Bindung. Für jeden erfolgreichen neuen Mutationsevent ist die Pending-Outbox am Commit zwingend, nicht bloss optionales Best Effort.

Bestehende OUs erhalten eine Anfangsrevision ohne erfundene rückwirkende Historie; deshalb muss nicht jeder Legacy-Datensatz eine neue Creation-Admission besitzen. Neue ursprüngliche Erstellungen halten ihren vollständigen Proof bereits vor dem Namespace-Write. Creation-/Mutation-Origin, Ownership und negatives Retirement werden nicht durch Row-Löschung entfernt. Kontrollierte Datenschutzlöschung, Retention und Off-host-Aufbewahrung sind weiterhin offene Betriebsanforderungen.

## Mehrfache Benutzer-OU-Zuordnungen: Migration 043

```mermaid
erDiagram
  IDENTITY_TENANTS ||--o{ IDENTITY_DIRECTORY_OU_MEMBERS : owns
  OUS ||--o{ IDENTITY_DIRECTORY_OU_MEMBERS : active_members
  USERS ||--o{ IDENTITY_DIRECTORY_OU_MEMBERS : belongs_to_units
  IDENTITY_DIRECTORY_OU_EVENTS ||--o| IDENTITY_DIRECTORY_OU_OUTBOX : pending_receipt
  IDENTITY_DIRECTORY_OU_MEMBERS {
    uuid id PK
    uuid tenant_id FK
    uuid ou_id FK
    uuid user_id FK
    timestamptz created_at
  }
```

OU/User ist zusätzlich eindeutig. Eine Person besitzt null bis viele aktive Zuordnungen; jede Beziehung gehört exakt einem Tenant, einer OU und einem User. Tatsächliche kanonische Hoheit aller drei Ziele wird beim Schreiben und Lesen geprüft, nicht aus unabhängigen FKs vermutet. Aktive OU-/User-FKs verwenden `RESTRICT`; lokale Ziel-Löschung ist bis zum ausdrücklichen Unlink ausgeschlossen. Seitenindex `(tenant_id,ou_id,created_at,id)`, Benutzerabhängigkeitsindex `(user_id,ou_id)` und der Index auf historischen Membership-IDs unterstützen diese Verträge.

`member-add`/`member-remove` verwenden dieselben OU-Events und Pending-Outbox aus 042. Der genaue aktive Datensatz bzw. ursprüngliche Before-Datensatz liegt in `proof.target.member`; jede Änderung erhöht die OU-Revision. Nach Unlink verschwindet nur die aktive Relation, nicht das historische Ereignis. Historische Events besitzen keinen FK auf später entfernte User-/OU-Rows; erneutes Zuordnen erzeugt eine frische UUID. Kein zweites Department-/Rollenregister, keine implizite Lizenzvergabe und kein als gelöst behaupteter Datenschutz-/Aufbewahrungsprozess. Siehe [vollständigen begrenzten Vertrag](../features/organization-memberships.md).

## Geräteinventar: Device-Migration 005

```mermaid
erDiagram
  DEVICES ||--o{ DEVICE_INVENTORY_ASSIGNMENTS : retains
  DEVICES ||--o{ DEVICE_INVENTORY_EVENTS : audit
  DEVICE_INVENTORY_EVENTS ||--o| DEVICE_INVENTORY_OUTBOX : pending_receipt
  DEVICE_INVENTORY_EVENTS ||--o| DEVICE_INVENTORY_ASSIGNMENTS : starts
  DEVICE_INVENTORY_EVENTS o|--o| DEVICE_INVENTORY_ASSIGNMENTS : releases
  DEVICES {
    varchar id PK
    uuid tenant_id
    text asset_id
    text serial_number
    bigint inventory_revision
    text inventory_lifecycle
    varchar assigned_user
  }
  DEVICE_INVENTORY_ASSIGNMENTS {
    uuid id PK
    uuid tenant_id
    varchar device_id FK
    uuid user_id
    jsonb target_snapshot
    timestamptz assigned_at
    timestamptz released_at
    uuid command_id FK
    uuid released_by_command_id FK
  }
  DEVICE_INVENTORY_EVENTS {
    uuid id PK
    uuid tenant_id
    varchar device_id FK
    text type
    integer version
    uuid correlation_id
    uuid actor_user_id
    jsonb proof
    jsonb before_state
    jsonb after_state
    jsonb before_assignment
    jsonb after_assignment
    timestamptz valid_until
    bigint transaction_id UK
  }
  DEVICE_INVENTORY_OUTBOX {
    uuid id PK,FK
    uuid tenant_id
    text status
    timestamptz created_at
  }
```

Dies ist die **separate Device-Datenbank**. Tenant/User/Actor-IDs sind geprüfte kanonische Referenzen mit damaligem Identity-Snapshot, keine behaupteten Cross-Database-FKs. `UNIQUE(device_id) WHERE released_at IS NULL` erlaubt genau eine aktuelle exklusive Zuweisung; die frühere wird bei Wechsel atomar geschlossen. Inventar-/Seriennummer sind je Tenant case-insensitiv eindeutig. Page-/History-/Recipient-Indizes dienen den wirklichen serverseitigen Abfragen. Im Erfolg muss jedes neue Event am Commit seine gleichnamige Pending-Outbox besitzen; der Creator-FK ist für Admission vor Device-Insert deferred.

Aktuelle Geräte und Historie werden in diesem Slice nicht über einen Delete-Endpunkt gelöscht; Raw-Delete/Truncate ist geschützt. Datenschutz-/Retention-/Archivierung ist weiterhin offen. Historische unowned Geräte bleiben bestehen und unsichtbar bis zu einem späteren ausdrücklich überprüften Adoptionsprozess. Es gibt keine automatische MDM-/Lizenzhoheit aus diesen Beziehungen; [Grenzen und Rollout](../features/device-inventory.md).

## Lizenz-Benutzerquellen: Migration 044

```mermaid
erDiagram
  IDENTITY_TENANTS ||--o{ IDENTITY_LICENSE_USER_SOURCES : owns
  IDENTITY_TENANTS ||--o{ IDENTITY_LICENSE_USER_SOURCE_EVENTS : retains
  IDENTITY_TENANTS ||--o{ IDENTITY_LICENSE_USER_SOURCE_OUTBOX : pending
  IDENTITY_LICENSE_USER_SOURCES ||--|{ IDENTITY_LICENSE_USER_SOURCE_EVENTS : logical_history
  IDENTITY_LICENSE_USER_SOURCE_EVENTS ||--|| IDENTITY_LICENSE_USER_SOURCE_OUTBOX : mandatory_receipt
  IDENTITY_LICENSE_USER_SOURCES {
    uuid id PK
    text issuer
    text client_id
    uuid tenant_id FK
    bigint client_revision
    bigint version
    boolean enabled
    uuid event_id UK
  }
  IDENTITY_LICENSE_USER_SOURCE_EVENTS {
    uuid id PK
    uuid source_id
    uuid tenant_id FK
    bigint source_version
    bigint client_revision
    name operator
    jsonb review
    jsonb before_state
    jsonb after_state
    bigint transaction_id UK
  }
  IDENTITY_LICENSE_USER_SOURCE_OUTBOX {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    jsonb payload
  }
```

Eine Source gehört genau einem bestehenden Tenant; `(issuer,client_id)` und `(source_id,source_version)` sind eindeutig. Die Source/Event-Beziehung ist ein durch Receiving-/Commit-Proof erzwungener logischer Vertrag, kein deklarierter Event→Source-FK: der ursprüngliche Event wird vor der neuen Source geschrieben. Das aktuelle `event_id` ist eindeutig, ebenfalls proofgebunden. Die Outbox besitzt einen echten FK zum Event; der vollständige Commit verlangt genau eine passende Pending-Receipt. Aktuelle State-Version und sämtliche JSON-Revisionswerte bleiben exakt als BIGINT-Strings erhalten.

Der getrennte Issuer bleibt Hoheit für Clientstatus/-revision. Es gibt keinen Cross-DB-FK, keinen Default-Tenant und keine automatische Bindung anhand eines Benutzers. Tenant-/Issuer-/Client-Herkunft bleibt unveränderlich, Clientrevision nur bewusst monoton aktualisierbar. Deaktivierung behält alle Belege; gewöhnliche Löschung/Truncate konfigurierter Quellen ist nicht erlaubt. Kontrollierte Datenschutz-/Retention-Verfahren und unabhängige Aufbewahrung bleiben offen. [API-/Operator-Vertrag](../features/tenant-license-sources.md).

## Firmen-Lizenzinventar: Policy-Migration 022

```mermaid
erDiagram
  LICENSE_CATALOG ||--o{ LICENSE_COMPANY_COMMANDS : original_admission
  LICENSE_CATALOG ||--o{ LICENSE_ASSIGNMENTS : existing_projection
  LICENSE_CATALOG ||--o{ LICENSE_ASSIGNMENT_SOURCES : existing_sources
  LICENSE_CATALOG ||--o{ LICENSE_GRANTS : existing_lineage
  LICENSE_COMPANY_COMMANDS ||--o{ LICENSE_COMPANY_ORIGINS : observes_actual_sql
  LICENSE_COMPANY_COMMANDS ||--|| LICENSE_COMPANY_EVENTS : final_receipt
  LICENSE_COMPANY_EVENTS ||--|| LICENSE_COMPANY_OUTBOX : pending
  LICENSE_CATALOG {
    uuid id PK
    uuid business_tenant_id
    bigint business_revision
    integer total_seats
    integer used_seats
  }
  LICENSE_SUBJECTS {
    varchar user_id PK
    uuid business_tenant_id
    boolean disabled
    bigint directory_revision
  }
  LICENSE_COMPANY_COMMANDS {
    uuid id PK
    uuid license_id FK
    uuid tenant_id
    uuid actor_user_id
    uuid target_user_id
    text action
    jsonb source
    jsonb command
    jsonb before_state
    timestamptz valid_until
    bigint transaction_id UK
  }
  LICENSE_COMPANY_ORIGINS {
    uuid id PK
    bigint ordinal PK
    uuid command_id FK
    text relation
    text operation
    jsonb before_state
    jsonb after_state
  }
  LICENSE_COMPANY_EVENTS {
    uuid id PK,FK
    uuid license_id FK
    uuid tenant_id
    text type
    integer version
    uuid correlation_id
    bigint before_revision
    bigint after_revision
    jsonb proof
    jsonb before_state
    jsonb after_state
  }
  LICENSE_COMPANY_OUTBOX {
    uuid id PK,FK
    uuid tenant_id
    text status
    timestamptz created_at
  }
```

Dies sind additive Felder/Tabellen der bestehenden **Policy-Datenbank**, kein zweites Lizenzsystem. Ein Pool hat null bis viele ursprüngliche Commands; jeder erfolgreich committed Command benötigt genau ein passendes finales Event und eine Pending-Outbox. Der Pool-FK am Command ist für Admission vor neuem Pool-Insert deferred; Event-/Outbox- und Effect-FKs sind real. `(license_id,after_revision)` und SQL-Transaktion sind eindeutig. Page-Indizes unterstützen echte Tenant-/Pool-/Historienabfragen.

Tenant und menschliche IDs besitzen hier bewusst keinen Cross-DB-FK zur Identity-Datenbank. Quelle und unveränderlicher Namespace werden vor/nach der Operation aktuell geprüft. Beide Ownership-Felder bleiben bei Legacy-Rows NULL; vorhandene Rechte-/Directory-/Providerhistorie wird nicht als leere neue Firma adoptiert. Raw-Löschung/Truncate aktueller Firmenbestände und Belege ist geschützt; kontrollierte Privacy-/Retention-Verfahren sind noch offen. [Vollständiger begrenzter Vertrag](../features/company-licenses.md).

## App- und Bestandskorrekturen: Policy 024

Policy **024** ergänzt am oben dargestellten Katalogmodell nur `update`-Commands und `app.license.pool.updated`-Events mit bestehender Original-Effect-/Pending-Kette. Kardinalitäten und Tabellen bleiben unverändert; kein neues Lizenzmodell und keine neue Benutzerzuweisung. Katalog-/Bestandsänderung erfolgt mit genau einer neuen Revision und unverändertem Namespace/Belegungsbestand. [Vertrag](../features/company-licenses.md#app--und-bestandskorrekturen).

## Dauerhaftes lokales Offboarding: Identity 045 und Policy 023

```mermaid
erDiagram
  IDENTITY_TENANTS ||--o{ IDENTITY_COMPANY_OFFBOARDING_RECEIPTS : owns
  IDENTITY_DIRECTORY_USER_EVENTS o|--o| IDENTITY_COMPANY_OFFBOARDING_RECEIPTS : actual_disable_only
  IDENTITY_COMPANY_OFFBOARDING_RECEIPTS ||--|| IDENTITY_COMPANY_OFFBOARDING_OUTBOX : pending
  COMPANY_OFFBOARDING_JOBS ||--|{ COMPANY_OFFBOARDING_EVENTS : retained_transitions
  COMPANY_OFFBOARDING_EVENTS ||--|| COMPANY_OFFBOARDING_OUTBOX : pending
  IDENTITY_COMPANY_OFFBOARDING_RECEIPTS {
    uuid tenant_id PK,FK
    uuid workflow_id PK
    uuid user_id
    uuid actor_user_id
    uuid operation_id FK,UK
    bigint expected_revision
    bigint before_revision
    bigint after_revision
    bigint before_eligibility_revision
    bigint after_eligibility_revision
    text action
    jsonb source
    timestamptz created_at
  }
  IDENTITY_COMPANY_OFFBOARDING_OUTBOX {
    uuid tenant_id PK,FK
    uuid workflow_id PK,FK
    text status
    timestamptz created_at
  }
  COMPANY_OFFBOARDING_JOBS {
    uuid tenant_id PK
    uuid id PK
    uuid user_id
    uuid created_by
    bigint revision
    jsonb intent
    jsonb state
    timestamptz created_at
    timestamptz updated_at
  }
  COMPANY_OFFBOARDING_EVENTS {
    uuid id PK
    uuid tenant_id FK
    uuid workflow_id FK
    bigint revision
    uuid actor_user_id
    bigint transaction_id UK
    jsonb authority
    jsonb before_state
    jsonb after_state
    timestamptz created_at
    timestamptz valid_until
  }
  COMPANY_OFFBOARDING_OUTBOX {
    uuid id PK,FK
    uuid tenant_id
    text status
    timestamptz created_at
  }
```

Erste drei Tabellen: nur Identity; letzte drei: nur Policy. Keine gezeichnete Cross-DB-FK- oder Atomaritätsbehauptung: der Identity-Checkpoint im Job wird über den ursprünglichen menschlichen Vertrag geprüft. Ein Tenant/Vorgang besitzt genau einen Identity-Beleg, jede reale Sperre höchstens einen referenzierten Directory-Event und jeder erfolgreich angelegte Policy-Job mindestens ein retained Event. `(tenant_id,workflow_id,revision)` ist im Journal eindeutig. Beide Outbox-Typen bleiben tatsächlich `pending`.

Die interne Identity-Tabelle `identity_company_offboarding_commit_checks` besitzt Transaktionsschlüssel und ursprünglichen Source-Proof; sie ist physischer Commit-Guard, keine zusätzliche Business-Entity. Lizenz-Assignment/-Grant/-Release-Belege bleiben im bestehenden Modell von Migration 022. Retention-/Löschbetrieb und vollständiges WF-004 sind offen. [Vertrag](../features/company-offboarding.md).

## Gruppenentzug beim Austritt: Identity 046

```mermaid
erDiagram
  IDENTITY_COMPANY_OFFBOARDING_RECEIPTS ||--o{ IDENTITY_COMPANY_OFFBOARDING_GROUP_RECEIPTS : original_account_checkpoint
  IDENTITY_DIRECTORY_GROUP_EVENTS ||--o| IDENTITY_COMPANY_OFFBOARDING_GROUP_RECEIPTS : actual_member_remove
  IDENTITY_COMPANY_OFFBOARDING_GROUP_RECEIPTS ||--|| IDENTITY_COMPANY_OFFBOARDING_GROUP_OUTBOX : pending
  IDENTITY_COMPANY_OFFBOARDING_GROUP_RECEIPTS {
    uuid id PK
    uuid tenant_id FK
    uuid workflow_id FK
    uuid user_id
    uuid group_id
    uuid membership_id
    uuid operation_id FK,UK
    uuid actor_user_id
    uuid correlation_id
    bigint before_group_revision
    bigint after_group_revision
    bigint eligibility_revision
    text name
    text reason
    jsonb source
    jsonb child_proof
    jsonb child_after
    timestamptz created_at
    timestamptz valid_until
    bigint transaction_id
  }
  IDENTITY_COMPANY_OFFBOARDING_GROUP_OUTBOX {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Alle dargestellten Tabellen gehören Identity; kein neuer Cross-DB-FK oder zweites Gruppenverzeichnis. Der Parent-FK ist zusammengesetzt aus Tenant/Vorgang; User-/Gruppen-/Membership-/Source-Kohärenz prüft der kanonische SQL-Vertrag. Kein FK zur gelöschten Live-Mitgliedschaft: Original-Child-Event, retained Membership-Origin und Before-/After-Belege tragen ihre Identität weiter. Ein Account-Checkpoint hat null bis viele erfolgreiche Gruppen-Children, jedes neue Child genau einen echten Group-Event und eine zwingende Pending-Outbox. Ein normaler Group-Event muss umgekehrt kein Offboarding-Child sein.

Zusätzlich besitzt `identity_company_offboarding_group_checks` einen Transaktionsschlüssel mit ursprünglichem Proof als internen Commit-Guard. Normale Änderungen/Löschung/Truncate dürfen die retained Kette nicht entfernen; kontrollierte Retention/Privacy bleibt offen. [Ausführbarer begrenzter Vertrag](../features/company-offboarding.md#gruppen-beim-austritt-entfernen).

## Rollen-PIM-Entzug beim Austritt: Identity 047

```mermaid
erDiagram
  IDENTITY_COMPANY_OFFBOARDING_RECEIPTS ||--o{ IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS : original_account_checkpoint
  IDENTITY_AUTHORITY_COMMAND_CHECKPOINTS ||--o| IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS : actual_canonical_child
  IDENTITY_ROLE_ASSIGNMENTS o|--o{ IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS : typed_role_grant
  IDENTITY_PIM_ELIGIBILITIES o|--o{ IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS : typed_eligibility_grant
  IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS ||--|| IDENTITY_COMPANY_OFFBOARDING_ACCESS_OUTBOX : pending
  IDENTITY_COMPANY_OFFBOARDING_ACCESS_RECEIPTS {
    uuid id PK
    uuid tenant_id FK
    uuid workflow_id FK
    uuid user_id
    text kind
    uuid resource_id
    uuid role_assignment_id FK
    uuid eligibility_id FK
    text role
    text version
    uuid checkpoint_id FK,UK
    uuid actor_user_id
    uuid correlation_id
    text reason
    bigint eligibility_revision
    jsonb source
    jsonb before_state
    jsonb after_state
    jsonb role_audit
    jsonb pim_audit
    jsonb authorization_audit
    jsonb record_audit
    timestamptz created_at
    timestamptz valid_until
    bigint transaction_id
  }
  IDENTITY_COMPANY_OFFBOARDING_ACCESS_OUTBOX {
    uuid id PK,FK
    uuid tenant_id FK
    text status
    timestamptz created_at
  }
```

Identity besitzt alle dargestellten Daten. Genau einer der beiden typisierten Grant-FKs ist gesetzt und gleich `resource_id`, abhängig von `kind`; die optionale ERD-Kante bedeutet nicht, dass beide fehlen dürfen. Parent-FK verwendet Tenant/Vorgang, der kanonische Vertrag prüft zusätzlich Benutzer und negative Eligibility. Ein ursprünglicher Grant kann in diesem Parent höchstens eine Receipt besitzen. Historische Beziehungen und ursprüngliche Audits bleiben erhalten; die Rolle ist keine neue oder kopierte Berechtigungsquelle.

`identity_company_offboarding_access_checks(transaction_id,source,before_state)` ist ein interner Commit-Guard. Die retained Kette einschliesslich tatsächlicher Authority-Checkpoint-Events/-Outbox ist keine externe Erfolgsbestätigung. Keine Cross-DB-FKs, allgemeine Lösch-/Retention-Abnahme oder vollständige Leaver-Bereinigung. [Vertrag](../features/company-offboarding-access.md).

## Geräterückgabe: Device 006

```mermaid
erDiagram
  DEVICES ||--o{ DEVICE_RETURN_REQUESTS : original_asset
  DEVICE_INVENTORY_ASSIGNMENTS ||--o{ DEVICE_RETURN_REQUESTS : original_assignment
  DEVICE_RETURN_REQUESTS ||--|{ DEVICE_RETURN_EVENTS : creation_and_optional_decision
  DEVICE_RETURN_EVENTS ||--|| DEVICE_RETURN_OUTBOX : pending
  DEVICE_INVENTORY_EVENTS o|--o| DEVICE_RETURN_EVENTS : actual_manual_return_release
  DEVICE_RETURN_REQUESTS {
    uuid id PK
    uuid tenant_id
    uuid workflow_id
    uuid user_id
    varchar device_id FK
    uuid assignment_id FK
    text asset_id
    text serial_number
    bigint revision
    bigint device_revision
    text status
    text reason
    uuid actor_user_id
    timestamptz requested_at
    bigint eligibility_revision
    timestamptz closed_at
    uuid closed_by_user_id
    uuid operation_id FK,UK
    uuid closing_operation_id FK,UK
    uuid inventory_operation_id FK
  }
  DEVICE_RETURN_EVENTS {
    uuid id PK
    uuid tenant_id
    uuid request_id FK
    varchar device_id FK
    uuid assignment_id FK
    text type
    integer version
    uuid actor_user_id
    uuid correlation_id
    timestamptz created_at
    jsonb before_state
    jsonb after_state
    uuid inventory_operation_id FK
    text reason
    jsonb before_request
    jsonb after_request
    jsonb proof
    timestamptz valid_until
    bigint transaction_id UK
  }
  DEVICE_RETURN_OUTBOX {
    uuid id PK,FK
    uuid tenant_id
    text status
    timestamptz created_at
  }
```

Alle dargestellten Relationen gehören Device. Ein Auftrag besitzt genau einen Erstellungs-Event, höchstens einen Abschluss-Event und reale Rückreferenz-FKs. Nur eine tatsächlich bestätigte Rückgabe referenziert den unveränderten 005-Release in derselben SQL-Transaktion. Normale Inventory-Events müssen keine Rückgabeentscheidung sein. Höchstens ein offener gespeicherter Auftrag pro ursprünglichem Assignment; alte abgebrochene Aufträge bleiben erhalten.

Tenant/Workflow/User aus Identity besitzen bewusst keinen datenbankübergreifenden FK. Deren ursprüngliche Herkunft wird als genau validierter 13-Feld-Snapshot unter ursprünglicher aktueller menschlicher Authority übernommen. `currentDeviceRevision` und `assignment_changed` sind echte aktuelle Projektionen, keine zweite aktive Geräte-/Assignment-Tabelle. Historische Rückgabe-Recovery darf keine spätere Zuweisung ändern. [Ausführbarer Vertrag und Grenzen](../features/device-returns.md).

## Eigene Blueprint-Entwürfe und immutable lokale Freigaben

```mermaid
erDiagram
  COMPANY_BLUEPRINTS ||--|{ COMPANY_BLUEPRINT_OPERATIONS : "original operations"
  COMPANY_BLUEPRINTS ||--o{ COMPANY_BLUEPRINT_VERSIONS : "immutable releases"
  COMPANY_BLUEPRINT_OPERATIONS ||--o| COMPANY_BLUEPRINT_VERSIONS : "published by"
  COMPANY_BLUEPRINT_OPERATIONS ||--|| COMPANY_BLUEPRINT_EVENTS : "metadata event"
  COMPANY_BLUEPRINT_EVENTS ||--|| COMPANY_BLUEPRINT_OUTBOX : "pending evidence"
  COMPANY_BLUEPRINTS {
    uuid id PK
    uuid tenant_id
    bigint revision
    integer published_version
    jsonb draft
    timestamptz created_at
    timestamptz updated_at
  }
  COMPANY_BLUEPRINT_OPERATIONS {
    uuid id PK
    uuid blueprint_id FK
    uuid tenant_id FK
    uuid actor_user_id
    jsonb command
    jsonb source
    jsonb application_source
    jsonb before_state
    jsonb after_state
    jsonb version_state
    timestamptz valid_until
    bigint transaction_id UK
  }
  COMPANY_BLUEPRINT_VERSIONS {
    uuid blueprint_id PK,FK
    integer version PK
    uuid tenant_id FK
    bigint source_revision
    bigint published_revision
    uuid operation_id FK,UK
    jsonb draft
    jsonb apps
  }
  COMPANY_BLUEPRINT_EVENTS {
    uuid id PK,FK
    uuid tenant_id FK
    uuid blueprint_id FK
    text type
    integer version
    bigint before_revision
    bigint after_revision
    integer released_version
    integer restored_from
  }
  COMPANY_BLUEPRINT_OUTBOX {
    uuid id PK,FK
    uuid tenant_id
    text status
  }
```

Alle dargestellten Relationen gehören Policy. Parent-FKs sind tenantgebunden; Blueprint-IDs werden nicht als globale Legacy-Blueprints übernommen. Die lokale Freigabe ist ein gespeichertes Artefakt, keine Deployment-Genehmigung. Entwurf und Freigabe besitzen begrenzte Konfigurationsdokumente, keine aktive Geräte- oder Lizenzprojektion. Gewünschte App-Pools werden unter ursprünglicher unabhängiger App-Authority gegen den tatsächlichen eigenen Katalog geprüft; Versionen halten historische Metadaten, keine dauerhaft gültige aktuelle Pool-Lease. Identity besitzt Tenant/Actor/Ownership separat. [Vertrag und offene Komposition](../features/company-blueprints.md).

## Firmen-Blueprint-Zuweisungen und Lizenzquellen: Migration 026/027

```mermaid
erDiagram
  COMPANY_BLUEPRINTS ||--o{ COMPANY_BLUEPRINT_VERSIONS : releases
  COMPANY_BLUEPRINT_USER_ASSIGNMENTS ||--o{ LICENSE_ASSIGNMENT_SOURCES : grants
  COMPANY_BLUEPRINT_ASSIGNMENT_OPERATIONS ||--o| COMPANY_BLUEPRINT_USER_ASSIGNMENTS : creates
  COMPANY_BLUEPRINT_ASSIGNMENT_OPERATIONS ||--o| COMPANY_BLUEPRINT_ASSIGNMENT_EVENTS : records
  COMPANY_BLUEPRINT_ASSIGNMENT_EVENTS ||--|| COMPANY_BLUEPRINT_ASSIGNMENT_OUTBOX : queues
  LICENSE_COMPANY_COMMANDS ||--o{ LICENSE_COMPANY_EVENTS : records
  LICENSE_COMPANY_COMMANDS ||--o{ LICENSE_COMPANY_ORIGINS : observes
  COMPANY_OFFBOARDING_V2_JOBS ||--o{ COMPANY_OFFBOARDING_V2_EVENTS : journals
  COMPANY_OFFBOARDING_V2_EVENTS ||--|| COMPANY_OFFBOARDING_V2_OUTBOX : queues
  COMPANY_BLUEPRINT_USER_ASSIGNMENTS {
    uuid id PK
    uuid tenant_id
    uuid user_id
    uuid blueprint_id FK
    integer version FK
    bigint eligibility_revision
    bigint revision
    text status
    uuid operation_id FK
    uuid removal_operation_id FK
  }
  COMPANY_BLUEPRINT_ASSIGNMENT_OPERATIONS {
    uuid id PK
    uuid tenant_id
    uuid actor_user_id
    uuid user_id
    text action
    jsonb command
    jsonb source
    jsonb application_source
    bigint transaction_id UK
  }
  LICENSE_COMPANY_COMMANDS {
    uuid id PK
    uuid license_id FK
    uuid parent_operation_id FK
    integer protocol
    jsonb before_state
    jsonb command
    bigint transaction_id
  }
  LICENSE_ASSIGNMENT_SOURCES {
    uuid license_id PK,FK
    text user_id PK
    text source_type PK
    text source_id PK
    uuid grant_id FK
  }
  COMPANY_OFFBOARDING_V2_JOBS {
    uuid id PK
    uuid tenant_id
    uuid user_id
    bigint revision
    jsonb intent
    jsonb state
  }
```

Die Zuweisungs-/Operations-/Event-/Outbox-Tabellen und V2-Workflowtabellen gehören Policy. Tenant/User-IDs bleiben kanonische Identity-IDs ohne Cross-DB-FKs. Eine effektive Seat-Zuordnung liegt weiterhin in `license_assignments`; mehrere manuelle/Blueprint-Quellen teilen diesen einen Sitz. Das Workflow-JSON hält ein vollständiges unveränderliches Quellen-/Binding-Manifest, einschliesslich app-freier Blueprints. Getrennte Datenbanktransaktionen von Identity und Policy werden nicht als atomar dargestellt. [Verhalten und Grenzen](../features/company-blueprint-assignments.md).

## Gruppenregeln: Identity 050

```mermaid
erDiagram
  identity_tenants ||--o{ identity_company_group_rules : actual_tenant_FK
  identity_company_group_rules ||--|{ identity_company_group_rule_events : configuration_FK
  identity_company_group_rule_events ||--|| identity_company_group_rule_outbox : original_event_FK
  identity_company_group_rules ||--o{ identity_company_group_rule_effects : actual_rule_FK
  identity_directory_group_events ||--o| identity_company_group_rule_effects : actual_event_PK_FK
  identity_membership_origins ||--o{ identity_company_group_rule_effects : original_membership_FK
  identity_company_group_rule_effects ||--|| identity_company_group_rule_effect_outbox : actual_effect_FK
```

Alle dargestellten Tabellen gehören Identity. Die Konfiguration speichert keine zweite Membership-Liste. Der aktuelle Gruppenbezug wird über die tatsächliche eigene kanonische Gruppe geprüft; ein FK auf deren löschbare Zeile würde die retained Historie verhindern. Untergruppen-/Ausnahme-UUIDs sind begrenzte, bei der Konfiguration geprüfte Referenzen in JSONB, keine hier behaupteten relationalen FKs. Originalmanifest, Event-/Pending-Fingerprints und physische Commit-Guards sichern den beschriebenen Schreibweg. Konfiguration und einzelne Membership-Effekte committen getrennt; der ursprüngliche 050-Pfad ist manuell, der folgende 051-Pfad ergänzt App-Jobs. [Modell und Grenzen](domain-model.md#gruppenregeln-identity-050), [UI/API/CLI](../features/company-group-rules.md).

## App-Gruppenregeln: Identity 051

```mermaid
erDiagram
  identity_automation_grants o|--o{ identity_membership_origins : optional_application_grant_FK
  identity_automation_jobs ||--o{ identity_company_group_rule_runs : actual_job_FK
  identity_automation_grants ||--o{ identity_company_group_rule_runs : actual_grant_FK
  identity_company_group_rules ||--o{ identity_company_group_rule_runs : actual_group_rule_FK
  identity_company_group_rule_runs ||--o{ identity_company_group_rule_steps : actual_run_FK
  identity_company_group_rule_effects o|--o{ identity_company_group_rule_steps : optional_actual_effect_FK
```

Alle dargestellten Tabellen gehören Identity. Job/Retry-Epoche/Zyklus und Run/User sind eindeutig. Die Work-Outbox ist über Original-Guards und Fingerprints an genau eine tatsächliche Run- oder Step-Zeile derselben Transaktion gebunden; sie hat keinen relationalen FK auf zwei unterschiedliche Tabellen. App-Origins behalten ihren echten Grant-FK und NULL als menschlichen Ersteller. Eine spätere tatsächliche Review-Entscheidung bleibt menschlich und unabhängig. [Teilmodell](domain-model.md#gruppenregeln-identity-050), [ausführbarer Ablauf und Grenzen](../features/company-group-rule-automation.md).

## App-Lizenzabgleich: Identity 049 und Policy 029

```mermaid
erDiagram
  identity_automation_grants ||--o{ identity_automation_jobs : actual_grant_FK
  identity_automation_schedules o|--o{ identity_automation_jobs : optional_schedule_FK
  company_license_groups ||--o{ company_license_automation_cycles : actual_rule_FK
  company_license_automation_cycles ||--o{ company_license_automation_pages : composite_cycle_FK
  company_license_automation_cycles ||--o{ company_license_automation_outbox : composite_cycle_FK
```

Die ersten drei Tabellen gehören Identity, die anderen Policy. Job-/Grant-/Tenant-IDs in einem Policy-Zyklus sind separat live gebundene Quellen, keine Cross-DB-FKs. Zyklus und Seiten sind je Job/Retry-Epoche/Zyklus und Seitenordinal eindeutig; Seite 0 der Pending-Outbox belegt die Erfassung. Seiten behalten echte geordnete Einzelresultate und Original-Actor/-Gruppenhash, nicht einen zweiten Sitzbestand. `identity_automation_jobs.progress` ist nur der bestätigte Fortschritt dieser getrennten Ausführung. [Modell und Grenzen](domain-model.md#appgebundener-lizenzabgleich-identity-049-und-policy-029), [ausführbarer Ablauf](../features/company-license-automation.md).

Identity 052 ergänzt keine Tabelle: Die [aktuelle Quellenprüfung](../features/company-group-live-sources.md) verwendet vorhandene Originalbelege, retained Revisionen und Review-Fristen. Snapshot-Quellenrevision und physischer Gruppen-ETag bleiben getrennt.
