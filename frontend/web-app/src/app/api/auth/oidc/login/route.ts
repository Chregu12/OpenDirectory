import { getBrowserAuth } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try { return await getBrowserAuth().login(); }
  catch { return Response.json({ error: 'browser_auth_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
}
