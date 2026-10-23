# OpenDirectory scripts

`node scripts/od.mjs --help` starts the dependency-free app-account and API automation CLI (Node.js 20+).

- `company-app list|get|create|enable|disable|rename|purpose|rotate|delete|history`: own [tenant-bound app accounts](../docs/features/company-apps.md) with original Owner/MFA, fixed supported purposes, conditional versions and creation recovery by request UUID. `list PAGE deleted` includes retained archived accounts.
- `app create`, `app enable`, `app disable`, `app rotate`: the separate global registry requires its existing application administration permissions; it does not manage company-owned clients.
- `automation enroll|approve|grants|queue|schedule|license-sync|group-sync|group-watch|license-watch|jobs|history|result|revoke|worker`: explicit own-company app grants, persistent export jobs and [scheduled group license reconciliation](../docs/features/company-license-automation.md). [Setup and worker lifecycle](../docs/features/company-automation.md).
- `group-rule get|configure|preview|sync|history`: explicit own-owner configuration and canonical reconciliation of [dynamic/nested groups](../docs/features/company-group-rules.md), preserving manual memberships and independent review. This command family requires the original human token/MFA. Unattended execution uses the separately granted [group-rule app action](../docs/features/company-group-rule-automation.md) through `automation group-sync`.
- `check`: authenticate an app and confirm its own active identity.
- `group create`, `group member add|remove`: ordinary groups and versioned memberships with the original authorized human token.
- `license-group list|link|sync|unlink`: own pool links and bounded per-user allocation; see [license groups](../docs/features/company-license-groups.md). Membership commands reconcile linked pools for actual company owners. Exit 2 reports blocked users; exit 1 may follow committed earlier steps.
- `request METHOD /api/path [body.json] [--if-match ETAG]`: perform a supported API operation with app credentials.

See [App-Konten und Skript-Automationen](../docs/features/app-accounts-automation.md) for setup, secret handling, Bash/PowerShell examples, scheduling with external runners and permission limits. App registration alone grants neither human roles nor mailbox/Graph access. Microsoft 365 is provisionally planned as the first mail adapter; mailbox provisioning remains unimplemented.

Run `npm run test:automation-client` from the repository root. Other service/operator scripts retain their documented prerequisites and authority boundaries.

`automation group-sync GRANT_ID GROUP_ID [INTERVAL_SECONDS]` führt gespeicherte eigene Gruppenregeln über die ausdrücklich genehmigte Aktion `directory.groups.reconcile` aus. Der vorhandene App-Worker braucht keine offene menschliche Sitzung; ausstehende unabhängige Reviews bleiben `partial`. [Einrichtung und Grenzen](../docs/features/company-group-rule-automation.md).

Die [aktuelle Gruppenquellenprüfung](../docs/features/company-group-live-sources.md) unterscheidet gespeicherte Links und effektive Regelquellen. Physische Mitgliedschaften und Lizenzsitze werden weiterhin separat abgeglichen. `automation group-watch GRANT_ID GROUP_ID` und `automation license-watch GRANT_ID RULE_ID` speichern [Beobachtungen tatsächlicher Quellen-/Bestandsänderungen](../docs/features/company-automation-changes.md); der bestehende App-Worker führt deren Abgleich ohne ein Minutenintervall aus.
