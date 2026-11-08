'use strict';

const { parseInventoryDetails } = require('./inventoryDetails');
const textFields = { name: 160, vendor: 255, category: 100, description: 2000, notes: 4000, icon_url: 2048 };
const fields = [...Object.keys(textFields), 'license_type', 'total_seats', 'cost_per_seat', 'currency', 'renewal_date', 'auto_approve', 'inventory_details'];

function parseCatalogInput(body, partial = false) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !fields.includes(key))) throw new Error('Unsupported license catalog fields');
  if (!partial && ['notes', 'icon_url'].some(key => Object.hasOwn(body, key))) throw new Error('notes and icon_url require an existing catalog entry');
  const result = {};
  for (const [key, value] of Object.entries(body)) {
    if (Object.hasOwn(textFields, key)) {
      if (value === null && !['name', 'category'].includes(key)) { result[key] = null; continue; }
      if (typeof value !== 'string' || value.length > textFields[key] || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) throw new Error('Invalid ' + key);
      const text = value.trim();
      if (key === 'name' && !text) throw new Error('name is required');
      result[key] = text || (key === 'category' ? 'Software' : null);
    } else if (key === 'inventory_details') result[key] = parseInventoryDetails(value);
    else if (key === 'total_seats') {
      if (!Number.isInteger(value) || value < 0 || value > 2147483647) throw new Error('total_seats must be a nonnegative integer');
      result[key] = value;
    } else if (key === 'cost_per_seat') {
      if (value !== null && (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 99999999.99 || Math.abs(value * 100 - Math.round(value * 100)) > 0.00001)) throw new Error('cost_per_seat must be a nonnegative amount with at most two decimals');
      result[key] = value;
    } else if (key === 'renewal_date') {
      if (value !== null && value !== '' && (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith('0000') || !Number.isFinite(Date.parse(value + 'T00:00:00Z')) || new Date(value + 'T00:00:00Z').toISOString().slice(0, 10) !== value)) throw new Error('Invalid renewal_date');
      result[key] = value || null;
    } else if (key === 'currency') {
      if (typeof value !== 'string' || !/^[A-Za-z]{3}$/.test(value)) throw new Error('currency must be a three-letter currency code');
      result[key] = value.toUpperCase();
    } else if (key === 'license_type') {
      if (!['per_user', 'per_device', 'concurrent', 'subscription'].includes(value)) throw new Error('Invalid license_type');
      result[key] = value;
    } else if (key === 'auto_approve') {
      if (typeof value !== 'boolean') throw new Error('auto_approve must be a boolean');
      result[key] = value;
    }
  }
  if (!partial && !result.name) throw new Error('name is required');
  if (partial && !Object.keys(result).length) throw new Error('At least one catalog field is required');
  return result;
}

module.exports = { parseCatalogInput };
