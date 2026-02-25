/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  // All API calls are proxied server-side to the integration service.
  // INTEGRATION_SERVICE_URL is a runtime env var set in the k8s deployment.
  // This way only the frontend is exposed externally - the backend stays internal.
  async rewrites() {
    const integrationUrl = process.env.INTEGRATION_SERVICE_URL || 'http://localhost:3005';
    return [
      { source: '/api/:path*',    destination: `${integrationUrl}/api/:path*` },
      { source: '/health',        destination: `${integrationUrl}/health` },
      { source: '/health/:path*', destination: `${integrationUrl}/health/:path*` },
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