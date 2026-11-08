import { getBrowserAuth, BrowserAuthError } from '@/server/browserAuth.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try { return await getBrowserAuth().login(request); }
  catch (error: any) {
    const invalidTarget = error instanceof BrowserAuthError && error.code === 'browser_auth_return_path_invalid';
    return Response.json({ error: invalidTarget ? 'browser_auth_return_path_invalid' : 'browser_auth_unavailable' }, { status: invalidTarget ? 400 : 503, headers: { 'Cache-Control': 'no-store' } });
  }
}
