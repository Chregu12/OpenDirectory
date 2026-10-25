import { createServiceProxy } from '@/lib/server/serviceProxy';

export const dynamic = 'force-dynamic';

const proxy = createServiceProxy('AUTH_SERVICE_URL', 'http://auth-service:3001');

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
