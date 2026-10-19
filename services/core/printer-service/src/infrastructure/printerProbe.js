'use strict';

// Infrastructure: raw network/IPP probing of a candidate printer IP.
// Pure protocol wrapper — no persistence, no business rules. Extracted
// verbatim from src/index.js so it can be unit-injected and reused by
// PrinterApplicationService without pulling in Express.

const net = require('net');
const ipp = (() => { try { return require('ipp'); } catch (_) { return null; } })();

function tcpProbe(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.connect(port, host);
  });
}

async function ippGetAttributes(host, port) {
  if (!ipp) return null;
  return new Promise((resolve) => {
    try {
      const printer = new ipp.Printer(`http://${host}:${port}/ipp/print`);
      printer.execute('Get-Printer-Attributes', {
        'operation-attributes-tag': { 'requested-attributes': ['printer-make-and-model', 'printer-info', 'document-format-supported'] },
      }, (err, res) => {
        if (err || !res) return resolve(null);
        const attrs = res?.['printer-attributes-tag'] ?? {};
        resolve({
          model: attrs['printer-make-and-model'] ?? attrs['printer-info'] ?? null,
          formats: attrs['document-format-supported'] ?? [],
        });
      });
      setTimeout(() => resolve(null), 4000);
    } catch (_) { resolve(null); }
  });
}

/**
 * Probe a candidate printer IP on the common printer ports.
 * @param {string} ip
 * @returns {Promise<object|null>} probe result, or null if nothing responded
 */
async function probe(ip) {
  const [ipp631, ipp443, raw9100, http80] = await Promise.all([
    tcpProbe(ip, 631),
    tcpProbe(ip, 443),
    tcpProbe(ip, 9100),
    tcpProbe(ip, 80),
  ]);

  if (!ipp631 && !ipp443 && !raw9100 && !http80) return null;

  const protocols = [];
  if (ipp631 || ipp443) protocols.push('IPP');
  if (raw9100)          protocols.push('RAW');
  if (http80)           protocols.push('HTTP');

  let model = null;
  let vendor = null;
  if (ipp631) {
    const attrs = await ippGetAttributes(ip, 631);
    if (attrs?.model) {
      model = attrs.model;
      vendor = model.split(/\s+/)[0];
    }
  }

  return {
    ip,
    vendor: vendor ?? 'Unknown',
    model:  model  ?? null,
    protocols,
    openPorts: { ipp: ipp631, ippSecure: ipp443, raw: raw9100, http: http80 },
  };
}

module.exports = { probe, tcpProbe, ippGetAttributes };
