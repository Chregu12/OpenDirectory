import { getBrowserAuth } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try { return await getBrowserAuth().companyRegistration(request, 'capabilities'); }
  catch { return Response.json({ error: 'company_registration_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
}
