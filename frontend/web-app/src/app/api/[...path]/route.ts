import { createServiceProxy } from '@/lib/server/serviceProxy';

export const dynamic = 'force-dynamic';

const proxy = createServiceProxy('API_BACKEND_URL', 'http://api-backend:8080');

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
