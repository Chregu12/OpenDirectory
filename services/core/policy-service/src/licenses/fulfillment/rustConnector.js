'use strict';

const { spawn } = require('node:child_process');
const { ProviderError } = require('./transport');

// Credentials cross only the private pipe; the child inherits no environment.
function runConnector({ binary, spawnImpl = spawn, request, signal, stage, field }) {
  return new Promise((resolve, reject) => {
    const writing = stage === 'graph_write';
    const failure = code => new ProviderError(code, { uncertain: writing });
    if (signal.aborted) return reject(failure(`${stage}_incomplete`));
    let child; let finished = false; let size = 0; const chunks = [];
    const finish = (error, rows) => {
      if (finished) return; finished = true; signal.removeEventListener('abort', abort);
      if (error) { child?.kill(); reject(error); } else resolve(rows);
    };
    const abort = () => finish(failure(`${stage}_incomplete`));
    try { child = spawnImpl(binary, [], { stdio: ['pipe', 'pipe', 'ignore'], env: {} }); }
    catch { return finish(failure(`${stage}_unavailable`)); }
    signal.addEventListener('abort', abort, { once: true });
    child.once('error', () => finish(failure(`${stage}_unavailable`)));
    child.stdin.on('error', () => finish(failure(`${stage}_unavailable`)));
    child.stdout.on('data', chunk => { size += chunk.length; if (size > 1_048_576) finish(failure(`${stage}_invalid_response`)); else chunks.push(chunk); });
    child.once('close', code => {
      if (finished) return;
      try {
        const reply = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (code !== 0 || !reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error();
        if (reply.ok === true && Object.keys(reply).sort().join(',') === ['ok', field].sort().join(',') && reply[field] !== null && typeof reply[field] === 'object') return finish(null, reply[field]);
        if (reply.ok === false && typeof reply.code === 'string' && new RegExp('^' + stage + '_[a-z0-9_]{1,80}$').test(reply.code)
          && Object.keys(reply).every(key => ['ok', 'code', 'retryAfter', ...(writing ? ['uncertain'] : [])].includes(key))
          && (!writing || typeof reply.uncertain === 'boolean')
          && (reply.retryAfter === undefined || Number.isInteger(reply.retryAfter) && reply.retryAfter >= 1 && reply.retryAfter <= 3600)) {
          const knownRejection = /^graph_write_(?:invalid_request|http_(?:400|401|403|404|405|410|412|415|422|429))$/.test(reply.code);
          return finish(new ProviderError(reply.code, { retryAfter: reply.retryAfter ?? null, uncertain: writing && (reply.uncertain || !knownRejection) }));
        }
      } catch {}
      finish(failure(`${stage}_invalid_response`));
    });
    if (signal.aborted) return abort();
    child.stdin.end(JSON.stringify(request));
  });
}
module.exports = { runConnector };
