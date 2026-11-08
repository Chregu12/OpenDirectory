export const dynamic = 'force-dynamic';

export async function GET() {
  const configured = process.env.PLATFORM_SERVICES;
  return Response.json({ configuredServices: configured === undefined ? null : configured.split(',').map(value => value.trim()).filter(Boolean) },
    { headers: { 'Cache-Control': 'no-store' } });
}
