'use strict';

async function readJson(url, timeoutMs = 3000) {
  const controller = new AbortController();
  // AbortSignal.timeout is unreferenced and can let the startup runner exit mid-request.
  const timer = setTimeout(() => controller.abort(new Error('Runtime HTTP deadline exceeded')), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: 'error' });
    return { status: response.status, ok: response.ok, body: await response.json() };
  } finally { clearTimeout(timer); }
}

module.exports = { readJson };
