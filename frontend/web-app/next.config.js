/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
  swcMinify: true,
  // All API calls are proxied server-side to the integration service.
  // INTEGRATION_SERVICE_URL is a runtime env var set in the k8s deployment.
  // This way only the frontend is exposed externally - the backend stays internal.
  async rewrites() {
    const integrationUrl       = process.env.INTEGRATION_SERVICE_URL        || 'http://integration-service:4000';
    const apiBackendUrl        = process.env.API_BACKEND_URL                || 'http://api-backend:8080';
    const printerUrl           = process.env.PRINTER_SERVICE_URL            || 'http://printer-service:3006';
    const appStoreUrl          = process.env.APP_STORE_URL                  || 'http://app-store:3906';
    const enterpriseDirUrl     = process.env.ENTERPRISE_DIRECTORY_URL       || 'http://enterprise-directory:3000';
    const conditionalAccessUrl = process.env.CONDITIONAL_ACCESS_URL         || 'http://conditional-access:3007';
    const quickActionsUrl      = process.env.QUICK_ACTIONS_URL              || 'http://quick-actions:3950';
    const authServiceUrl       = process.env.AUTH_SERVICE_URL               || 'http://auth-service:3001';
    const identityServiceUrl   = process.env.IDENTITY_SERVICE_URL           || 'http://identity-service:3001';
    const deviceServiceUrl     = process.env.DEVICE_SERVICE_URL             || 'http://device-service:3003';
    const sambaUrl             = process.env.SAMBA_SERVICE_URL              || 'http://samba-ad-dc:3010';
    const complianceEngineUrl  = process.env.COMPLIANCE_ENGINE_URL          || 'http://compliance-engine:3907';
    const auditServiceUrl      = process.env.AUDIT_SERVICE_URL              || 'http://audit-service:3908';
    const networkInfraUrl      = process.env.NETWORK_INFRA_URL              || 'http://network-infrastructure:3007';
    const leastPrivilegeUrl    = process.env.LEAST_PRIVILEGE_URL            || 'http://least-privilege:3011';
    return [
      // OIDC endpoints → auth-service (same-origin, avoids CORS)
      { source: '/oidc/:path*', destination: `${authServiceUrl}/:path*` },
      // Health + integration-specific routes -> integration-service
      { source: '/health',                  destination: `${integrationUrl}/health` },
      { source: '/health/:path*',           destination: `${integrationUrl}/health/:path*` },
      { source: '/api/lldap/:path*',        destination: `${integrationUrl}/api/lldap/:path*` },
      { source: '/api/grafana/:path*',      destination: `${integrationUrl}/api/grafana/:path*` },
      { source: '/api/prometheus/:path*',   destination: `${integrationUrl}/api/prometheus/:path*` },
      { source: '/api/vault/:path*',        destination: `${integrationUrl}/api/vault/:path*` },
      { source: '/api/config/modules',      destination: `${integrationUrl}/api/config/modules` },
      { source: '/api/config/modules/:p*',  destination: `${integrationUrl}/api/config/modules/:p*` },
      { source: '/api/config/features',     destination: `${integrationUrl}/api/config/features` },
      { source: '/api/config/settings',     destination: `${integrationUrl}/api/config/settings` },
      { source: '/api/services/:path*',     destination: `${integrationUrl}/api/services/:path*` },
      { source: '/api/services',            destination: `${integrationUrl}/api/services` },
      // Printer service routes -> printer-service
      { source: '/api/printer/:path*',      destination: `${printerUrl}/api/printer/:path*` },
      // Device drivers & hardware detection -> device-service (must come
      // before the /api/:path* catch-all; api-backend has none of these routes)
      { source: '/api/devices/drivers',                        destination: `${deviceServiceUrl}/api/drivers` },
      { source: '/api/devices/drivers/:path*',                 destination: `${deviceServiceUrl}/api/drivers/:path*` },
      { source: '/api/devices/report-hardware',                destination: `${deviceServiceUrl}/api/devices/report-hardware` },
      { source: '/api/devices/report-hardware/:id',            destination: `${deviceServiceUrl}/api/devices/report-hardware/:id` },
      { source: '/api/devices/:id/driver-recommendations',     destination: `${deviceServiceUrl}/api/devices/:id/driver-recommendations` },
      { source: '/api/devices/:id/detect-drivers',             destination: `${deviceServiceUrl}/api/devices/:id/detect-drivers` },
      // App Store routes -> app-store service
      { source: '/api/store/:path*',        destination: `${appStoreUrl}/api/store/:path*` },
      { source: '/api/appstore/:path*',     destination: `${appStoreUrl}/api/appstore/:path*` },
      // Compliance dashboard/baselines/waivers/frameworks/reports ->
      // compliance-engine service (must come before the /api/:path*
      // catch-all; api-backend has none of these routes).
      { source: '/api/compliance/:path*',   destination: `${complianceEngineUrl}/api/compliance/:path*` },
      // Network infrastructure (DHCP/shares/discovery/monitoring/devices) ->
      // network-infrastructure service. This prefix had no rewrite rule at
      // all, so every /api/network/* call (api.ts, NetworkInfrastructureIntegration,
      // PrintersView/PoliciesView/AppStoreView's /api/network/shares) was
      // silently falling through to the api-backend catch-all. Must come
      // before the /api/:path* catch-all.
      { source: '/api/network/:path*',      destination: `${networkInfraUrl}/api/network/:path*` },
      // DNS management: some call sites (NetworkInfrastructureIntegration's
      // records list/create/delete) still use the wrong /api/dns/* prefix
      // instead of /api/network/dns/*. Rewrite the path (not just the host)
      // so those keep working too — must come before the /api/:path* catch-all.
      { source: '/api/dns/:path*',          destination: `${networkInfraUrl}/api/network/dns/:path*` },
      // Audit trail routes are split across two services that both mount
      // paths under /api/audit/*: enterprise-directory owns the
      // directory-change audit log (/log, /objects/:dn/history,
      // /actors/:id/activity); audit-service owns everything else (events,
      // timeline, stats, categories, search, integrity, reports, alerts,
      // retention, SIEM). The enterprise-directory rules must precede the
      // audit-service catch-all below, or they would be shadowed by it.
      { source: '/api/audit/log',           destination: `${enterpriseDirUrl}/api/audit/log` },
      { source: '/api/audit/objects/:path*',destination: `${enterpriseDirUrl}/api/audit/objects/:path*` },
      { source: '/api/audit/actors/:path*', destination: `${enterpriseDirUrl}/api/audit/actors/:path*` },
      { source: '/api/audit/:path*',        destination: `${auditServiceUrl}/api/audit/:path*` },
      // PIM sessions & break-glass -> conditional-access service (port 3007)
      { source: '/api/v1/pim/:path*',       destination: `${conditionalAccessUrl}/api/v1/pim/:path*` },
      // Quick actions (compliance snapshot, policy deploy) -> quick-actions service (port 3950)
      { source: '/api/quick/:path*',        destination: `${quickActionsUrl}/api/quick/:path*` },
      // Samba AD DC service routes -> samba-ad-dc (must come before the
      // /api/:path* catch-all; api-backend has none of these routes).
      // /api/computers/join et al. are mounted without the /samba prefix
      // on the backend, so that specific rule must come first.
      { source: '/api/samba/computers/:path*', destination: `${sambaUrl}/api/computers/:path*` },
      { source: '/api/samba/:path*',           destination: `${sambaUrl}/api/samba/:path*` },
      // Least-privilege service: permission matrix / unused-permission
      // sweeps / risk scores (/api/permissions/*) and its own JIT resource
      // elevation flow (/api/pim/elevation/*), consumed by PermissionsView.tsx.
      // /api/pim/elevation is a deliberately distinct prefix from bare
      // /api/pim/* — see services/core/least-privilege/src/index.js for why:
      // authentication-service's directory-role PIM (consumed by PIMView.tsx)
      // and this service's resource/level JIT elevation are different
      // features that happened to collide on the same path, not the same
      // feature twice. Neither had a rewrite rule before, so both silently
      // fell through to the api-backend catch-all (which has no handlers for
      // them) and PermissionsView.tsx ran on demo data only.
      { source: '/api/permissions/:path*',  destination: `${leastPrivilegeUrl}/api/permissions/:path*` },
      { source: '/api/pim/elevation/:path*', destination: `${leastPrivilegeUrl}/api/pim/elevation/:path*` },
      // PIM (Privileged Identity Management) roles & approval queue ->
      // authentication-service (consumed by PIMView.tsx: GET/POST
      // /api/pim/roles, PUT/DELETE /api/pim/roles/:id, GET/POST
      // /api/pim/requests, POST /api/pim/requests/:id/{approve,deny,revoke} —
      // see services/core/authentication-service/src/routes/pim.js). This is
      // a DIFFERENT feature from /api/pim/elevation/* (least-privilege,
      // resource/level JIT elevation) and /api/v1/pim/* (conditional-access,
      // break-glass sessions) above — they only share the "pim" word. The
      // narrower /api/pim/elevation/:path* rule MUST precede this broader
      // /api/pim/:path* rule, or it would shadow it.
      { source: '/api/pim/:path*',          destination: `${authServiceUrl}/api/pim/:path*` },
      // Additional authentication-service routes beyond what api-backend
      // implements. api-backend (services/platform/api-backend/server.js)
      // only implements four /api/auth/* routes: login, logout, profile
      // (GET/PUT), change-password — those MUST keep going to api-backend
      // (pinned below as literals) since they work there today. Every other
      // /api/auth/* path — register, refresh, validate, sessions*,
      // trust-score, verify-device, verify-location, step-up, mfa/*,
      // reset-password, password-reset/confirm, users* (admin), sso*,
      // audit/login-history, audit/security-events — is only implemented by
      // authentication-service (see src/routes/{auth,mfa,sessions,zeroTrust,
      // users,sso,audit}.js) and was silently 404ing via the api-backend
      // catch-all. The four literals MUST precede this broad rule, or they'd
      // be shadowed by it.
      { source: '/api/auth/login',           destination: `${apiBackendUrl}/api/auth/login` },
      { source: '/api/auth/logout',          destination: `${apiBackendUrl}/api/auth/logout` },
      { source: '/api/auth/profile',         destination: `${apiBackendUrl}/api/auth/profile` },
      { source: '/api/auth/change-password', destination: `${apiBackendUrl}/api/auth/change-password` },
      { source: '/api/auth/:path*',          destination: `${authServiceUrl}/api/auth/:path*` },
      // Service accounts (SettingsView / service-account management) ->
      // authentication-service (src/routes/serviceAccounts.js). quick-actions
      // already calls this service directly server-to-server; this rule adds
      // the browser-facing path.
      { source: '/api/service-accounts',       destination: `${authServiceUrl}/api/service-accounts` },
      { source: '/api/service-accounts/:path*', destination: `${authServiceUrl}/api/service-accounts/:path*` },
      // Domain configuration (OnboardingWizard) -> authentication-service
      // (src/routes/directory.js: GET/POST /api/config/domain). Distinct
      // from the /api/config/{modules,features,settings} rules above, which
      // target integration-service.
      { source: '/api/config/domain',       destination: `${authServiceUrl}/api/config/domain` },

      // Organizational units -> identity-service, the canonical OU owner.
      // (authentication-service briefly had a competing /api/ous backed by a
      // second table in its own DB; that was consolidated away — identity-service
      // owns the directory entities and already serves /api/users, /api/groups,
      // /api/roles.) Without this rule /api/ous falls into the api-backend
      // catch-all below and 404s.
      { source: '/api/ous',                 destination: `${identityServiceUrl}/api/ous` },
      { source: '/api/ous/:path*',          destination: `${identityServiceUrl}/api/ous/:path*` },
      // ── NOT routed (investigated, deliberately left as-is) ──────────────
      // /api/devices/:id/{software,hardware,network,logs,policies,compliance},
      // /api/mdm/*, /api/policies/{ou-tree,templates,:id/compiled,
      // :id/versions,:id/gpos}, /api/monitoring/status,
      // /api/security/{pam/sessions,dlp/policies}, /api/gateway/stats:
      // these handlers exist ONLY in services/platform/integration-service/
      // index.js, a pre-DDD-rewrite file that is NOT part of what actually
      // runs. package.json's "start" script runs `node dist/index.js`,
      // compiled by tsc from tsconfig.json's `rootDir: "./src"` /
      // `include: ["src/**/*"]` — the top-level index.js is outside that
      // tree and is never built into dist/ or executed. The real, deployed
      // integration-service (src/index.ts + src/routes/*.ts) only mounts
      // lldap, grafana, prometheus, vault, config and services. Pointing
      // these paths at integration-service would trade one 404 (api-backend
      // catch-all) for another (integration-service's own 404 handler) —
      // no reachability gained. /api/mdm/* additionally has THREE competing
      // candidate backends with no clear owner: apple-mdm (real, deployed,
      // docker-compose port 3014, implements /api/mdm/devices + device
      // commands), quick-actions' own 'mdm' service alias (MDM_SERVICE_URL,
      // defaults to http://mobile-management — a host that doesn't appear in
      // docker-compose.yml at all), and the dead integration-service code
      // above. /api/policies/{ou-tree,templates,:id/compiled,...} similarly
      // has no real implementation: policy-service (real, deployed, port
      // 3004) has policy CRUD/assign/deploy/compliance-scan but none of
      // these sub-routes. Resolving any of this requires a service-level
      // decision (which backend should own the route, and building/wiring
      // it there) — out of scope for a routing-layer change, and explicitly
      // out of scope for this task (no service files touched). Left as-is
      // rather than blindly rerouted.
      // Everything else -> api-backend
      { source: '/api/:path*',              destination: `${apiBackendUrl}/api/:path*` },
    ];
  },
  env: {
    // Points to the same origin so browser requests go through Next.js rewrites
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || '',
  },
  images: {
    domains: ['localhost'],
  },
  experimental: {
    appDir: true,
  },
};

module.exports = nextConfig;
