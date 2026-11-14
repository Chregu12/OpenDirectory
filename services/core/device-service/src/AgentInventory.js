'use strict';
const fail = () => { throw Object.assign(new Error('Exact bounded agent inventory required'), { status: 400 }); };
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) fail();
}
function counter(value, positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value) || BigInt(value).toString() !== value || BigInt(value) > 9223372036854775807n || positive && value === '0') fail();
}
function capacity(value) {
  if (value === null) return;
  exact(value, ['totalBytes', 'availableBytes']); counter(value.totalBytes, true); counter(value.availableBytes);
  if (BigInt(value.availableBytes) > BigInt(value.totalBytes)) fail();
}
function validateInventory(value) {
  exact(value, ['schemaVersion', 'cpu', 'memory', 'systemDisk', 'uptimeSeconds']);
  if (value.schemaVersion !== 1) fail();
  if (value.cpu !== null) {
    exact(value.cpu, ['model', 'logicalProcessors']);
    if (typeof value.cpu.model !== 'string' || value.cpu.model.trim() !== value.cpu.model || [...value.cpu.model].length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(value.cpu.model)
      || !Number.isSafeInteger(value.cpu.logicalProcessors) || value.cpu.logicalProcessors < 1 || value.cpu.logicalProcessors > 65536) fail();
  }
  capacity(value.memory); capacity(value.systemDisk);
  if (value.uptimeSeconds !== null) counter(value.uptimeSeconds);
  return value;
}
module.exports = { validateInventory };
