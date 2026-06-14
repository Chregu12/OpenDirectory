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
      // App Store routes -> app-store service
      { source: '/api/store/:path*',        destination: `${appStoreUrl}/api/store/:path*` },
      { source: '/api/appstore/:path*',     destination: `${appStoreUrl}/api/appstore/:path*` },
      // Audit log -> enterprise-directory service (port 3000)
      { source: '/api/audit/:path*',        destination: `${enterpriseDirUrl}/api/audit/:path*` },
      // PIM sessions & break-glass -> conditional-access service (port 3007)
      { source: '/api/v1/pim/:path*',       destination: `${conditionalAccessUrl}/api/v1/pim/:path*` },
      // Quick actions (compliance snapshot, policy deploy) -> quick-actions service (port 3950)
      { source: '/api/quick/:path*',        destination: `${quickActionsUrl}/api/quick/:path*` },
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
