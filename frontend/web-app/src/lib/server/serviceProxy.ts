export function createServiceProxy(envName: string, fallback: string) {
  return async function proxyRequest(request: Request): Promise<Response> {
    try {
      const incoming = new URL(request.url);
      const target = new URL(`${incoming.pathname}${incoming.search}`, process.env[envName] || fallback);
      const headers = new Headers(request.headers);
      for (const name of ['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding']) headers.delete(name);

      const response = await fetch(target, {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
        cache: 'no-store',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
      });
      const responseHeaders = new Headers(response.headers);
      for (const name of ['connection', 'content-length', 'content-encoding', 'transfer-encoding']) responseHeaders.delete(name);
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
    } catch {
      return Response.json({ error: 'Service unavailable' }, { status: 502 });
    }
  };
}
