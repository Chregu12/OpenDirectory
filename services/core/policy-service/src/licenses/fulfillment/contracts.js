'use strict';

const { LicenseError } = require('../LicenseError');
const { UUID } = require('../LicensePrincipal');
function fail(status, code) { throw new LicenseError(status,code); }
function uuid(value) { if (typeof value !== 'string' || !UUID.test(value)) fail(400,'canonical_uuid_required'); return value; }
function fields(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== allowed.length || allowed.some(field=>!Object.hasOwn(value,field))) fail(400,'invalid_fulfillment_fields');
}
function reason(value) {
  if (typeof value !== 'string' || value.trim().length < 10 || value.length > 500 || /[\u0000-\u001f\u007f]/.test(value)) fail(400,'reviewed_reason_required'); return value.trim();
}
function plans(value) {
  if (!Array.isArray(value) || value.length > 128 || value.some((item,index)=>!UUID.test(item) || index>0 && value[index-1]>=item)) fail(400,'sorted_unique_plan_uuids_required');
  return value;
}
function etag(kind,id,version) { return `"od-fulfillment:${kind}:${id}:${version}"`; }
function conditional(value,kind,row) {
  if (!value) fail(428,'version_required');
  if (value !== etag(kind,row.id,String(row.version))) fail(412,'fulfillment_version_changed');
}
module.exports = { fail,uuid,fields,reason,plans,etag,conditional };
