import { getBrowserAuth } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try { return await getBrowserAuth().companyRegistration(request, 'submit'); }
  catch { return Response.json({ error: 'company_registration_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
}
