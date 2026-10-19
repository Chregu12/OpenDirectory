import { getBrowserAuth } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try { return await getBrowserAuth().recovery(request, 'confirm'); }
  catch { return Response.json({ error: 'browser_auth_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
}
