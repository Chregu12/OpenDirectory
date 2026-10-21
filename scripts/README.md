# OpenDirectory scripts

`node scripts/od.mjs --help` starts the dependency-free app-account and API automation CLI (Node.js 20+).

- `app create`, `app enable`, `app disable`, `app rotate`: use an authorized human administrator access token and the existing OAuth registry.
- `check`: authenticate an app and confirm its own active identity.
- `request METHOD /api/path [body.json] [--if-match ETAG]`: perform a supported API operation with app credentials.

See [App-Konten und Skript-Automationen](../docs/features/app-accounts-automation.md) for setup, secret handling, Bash/PowerShell examples, scheduling with external runners and permission limits. App registration alone grants neither human roles nor mailbox/Graph access. Mail-provider selection remains pending.

Run `npm run test:automation-client` from the repository root. Other service/operator scripts retain their documented prerequisites and authority boundaries.
