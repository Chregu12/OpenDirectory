import { getBrowserAuth } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request, context: { params: Promise<{ operation: string }> }) {
  try { return await getBrowserAuth().employeeInvitationOwner(request, (await context.params).operation); }
  catch { return Response.json({ error: 'employee_invitation_owner_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' } }); }
}
