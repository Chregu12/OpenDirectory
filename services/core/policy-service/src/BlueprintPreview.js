'use strict';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PLATFORMS = ['windows', 'macos', 'linux'];
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function previewValues(body) {
  if (!exact(body, ['platform', 'blueprints']) || !PLATFORMS.includes(body.platform) || !Array.isArray(body.blueprints)
    || body.blueprints.length < 1 || body.blueprints.length > 25) fail(400, 'exact_blueprint_preview_required');
  const identifiers = new Set();
  for (const item of body.blueprints) {
    if (!exact(item, ['id', 'version']) || typeof item.id !== 'string' || !UUID.test(item.id)
      || !Number.isInteger(item.version) || item.version < 1 || item.version > 2147483647 || identifiers.has(item.id)) fail(400, 'exact_blueprint_preview_required');
    identifiers.add(item.id);
  }
  return { platform: body.platform, blueprints: body.blueprints.map(item => ({ id: item.id, version: item.version })) };
}
function checkJson(value, depth = 0) {
  if (depth > 20) fail(503, 'blueprint_preview_source_unavailable');
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.forEach(item => checkJson(item, depth + 1));
  if (!record(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(503, 'blueprint_preview_source_unavailable');
  for (const key of Object.keys(value)) {
    if (['__proto__', 'prototype', 'constructor'].includes(key)) fail(503, 'blueprint_preview_source_unavailable');
    checkJson(value[key], depth + 1);
  }
}
function resolveConfigurations(rows) {
  if (!Array.isArray(rows)) fail(503, 'blueprint_preview_source_unavailable');
  if (rows.length > 1000) fail(409, 'blueprint_preview_limit_reached');
  const groups = new Map(); const identifiers = new Set(); let payloadBytes = 0;
  for (const row of rows) {
    if (!row || typeof row.id !== 'string' || !UUID.test(row.id) || typeof row.blueprint_id !== 'string' || !UUID.test(row.blueprint_id)
      || identifiers.has(row.id) || typeof row.config_type !== 'string' || !row.config_type.trim() || row.config_type.length > 100
      || /[\u0000-\u001f\u007f-\u009f]/.test(row.config_type) || typeof row.payload_json !== 'string'
      || typeof row.payload_rank !== 'string' || !/^[1-9][0-9]{0,3}$/.test(row.payload_rank) || Number(row.payload_rank) > 1000) fail(503, 'blueprint_preview_source_unavailable');
    identifiers.add(row.id);
    payloadBytes += Buffer.byteLength(row.payload_json);
    if (payloadBytes > 1048576) fail(409, 'blueprint_preview_limit_reached');
    let payload;
    try { payload = JSON.parse(row.payload_json); } catch { fail(503, 'blueprint_preview_source_unavailable'); }
    if (!record(payload)) fail(503, 'blueprint_preview_source_unavailable');
    checkJson(payload);
    if (!groups.has(row.config_type)) groups.set(row.config_type, new Map());
    const variants = groups.get(row.config_type);
    if (!variants.has(row.payload_rank)) variants.set(row.payload_rank, { payloadJson: row.payload_json, sources: [] });
    variants.get(row.payload_rank).sources.push({ blueprintId: row.blueprint_id, configurationId: row.id });
  }
  const effectiveConfigurations = []; const conflicts = [];
  for (const configType of [...groups.keys()].sort()) {
    const variants = [...groups.get(configType).entries()].sort(([left], [right]) => Number(left) - Number(right)).map(([, value]) => {
      value.sources.sort((left, right) => `${left.blueprintId}:${left.configurationId}`.localeCompare(`${right.blueprintId}:${right.configurationId}`));
      return value;
    });
    if (variants.length > 1) conflicts.push({ configType, variants });
    else effectiveConfigurations.push({ configType, ...variants[0] });
  }
  return { configurationCount: rows.length, hasConflicts: conflicts.length > 0, effectiveConfigurations, conflicts };
}

async function readConfigurations(client, identifiers) {
  return (await client.query('SELECT id,blueprint_id,config_type,payload::text AS payload_json,dense_rank() OVER (PARTITION BY config_type ORDER BY payload) AS payload_rank FROM blueprint_configurations WHERE blueprint_id=ANY($1::uuid[]) ORDER BY blueprint_id,id LIMIT 1001', [identifiers])).rows;
}

module.exports = { previewValues, resolveConfigurations, readConfigurations };
