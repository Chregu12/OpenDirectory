/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  async rewrites() {
    return [
      {
        source: '/api/integration/:path*',
        destination: `${process.env.INTEGRATION_SERVICE_URL || 'http://localhost:3005'}/api/:path*`,
      },
      {
        source: '/api/health/:path*',
        destination: `${process.env.INTEGRATION_SERVICE_URL || 'http://localhost:3005'}/health/:path*`,
      },
    ];
  },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3005',
    NEXT_PUBLIC_GRAFANA_URL: process.env.NEXT_PUBLIC_GRAFANA_URL || 'http://localhost:30300',
    NEXT_PUBLIC_LLDAP_URL: process.env.NEXT_PUBLIC_LLDAP_URL || 'http://localhost:30170',
    NEXT_PUBLIC_PROMETHEUS_URL: process.env.NEXT_PUBLIC_PROMETHEUS_URL || 'http://localhost:30909',
    NEXT_PUBLIC_VAULT_URL: process.env.NEXT_PUBLIC_VAULT_URL || 'http://localhost:30820',
  },
  images: {
    domains: ['localhost'],
  },
  experimental: {
    appDir: true,
  },
};

module.exports = nextConfig;