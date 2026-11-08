'use strict';
const fields = new Set(['reference', 'orderReference', 'supplier', 'receivedDate']);
function parseInventoryDetails(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !fields.has(key))) throw new Error('Invalid license inventory fields');
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== 'string' || item.length > 255 || /[\u0000-\u001f\u007f]/.test(item)) throw new Error('License inventory fields must be short text');
    const text = item.trim();
    if (key === 'receivedDate' && text && (!/^\d{4}-\d{2}-\d{2}$/.test(text) || text.startsWith('0000') || !Number.isFinite(Date.parse(text+'T00:00:00Z')) || new Date(text+'T00:00:00Z').toISOString().slice(0,10) !== text)) throw new Error('Invalid received date');
    result[key] = text;
  }
  return result;
}
module.exports = { parseInventoryDetails };
