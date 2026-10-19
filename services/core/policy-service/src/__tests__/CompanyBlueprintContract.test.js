'use strict';

const { randomUUID } = require('node:crypto');
const { COMPANY_BLUEPRINT_PERMISSIONS, draftValues, payloadValues, writeValues, commandValues, etag, expectedRevision, pagination, validSource } = require('../../../../../packages/company-blueprint-contract');
const blueprintId = randomUUID(); const userId = randomUUID(); const tenantId = randomUUID();
const draft = () => ({ name: 'Own security baseline', description: '', platform: 'macos', configurations: [{ id: randomUUID(), type: 'screen_lock', name: 'Screen lock', payloadJson: '{"minutes":5,"requirePassword":true}' }], appPoolIds: [] });
const write = () => ({ id: blueprintId, draft: draft(), reason: 'Explicit own baseline creation', confirm: true });
function actor() { const authTime = Math.floor(Date.now() / 1000); return { actor_type: 'user', token_use: 'access', iss: 'https://company-blueprints.test', sub: 'actual-owner', jti: randomUUID(), exp: authTime + 3600, auth_time: authTime, amr: ['pwd', 'otp'], identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } }; }
function source(user) { return { schemaVersion: 1, companyBlueprintProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization, tenant: { id: tenantId, version: '1', generation: '1' }, actorUserId: userId, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS], validUntil: user.auth_time + 300 }; }
const reject = operation => expect(operation).toThrow(expect.objectContaining({ status: 400 }));

test('captures typed non-secret draft values independently of mutable callers', () => {
  const input = draft(); const captured = draftValues(input); input.configurations[0].name = 'Changed caller'; input.appPoolIds.push(randomUUID());
  expect(captured.configurations[0].name).toBe('Screen lock'); expect(captured.appPoolIds).toEqual([]);
});
test.each([
  ['screen_lock', '{"minutes":1,"requirePassword":false}'], ['screen_lock', '{"minutes":1440,"requirePassword":true}'],
  ['filevault', '{"enabled":true}'], ['filevault', '{"enabled":false}'],
  ['software_update', '{"automatic":true,"deferralDays":0}'], ['software_update', '{"automatic":false,"deferralDays":365}'],
])('accepts explicitly supported local %s values %#', (type, payload) => { expect(payloadValues(type, payload)).toBe(payload); });
test.each([
  ['wifi', '{"password":"never retain raw credentials"}'], ['vpn', '{}'], ['certificate', '{}'],
  ['screen_lock', '{"minutes":5,"requirePassword":true,"password":"not supported"}'],
  ['screen_lock', '{"minutes":0,"requirePassword":true}'], ['screen_lock', '{"minutes":1441,"requirePassword":true}'],
  ['screen_lock', '{"minutes":"5","requirePassword":true}'], ['screen_lock', '{"minutes":5,"requirePassword":1}'],
  ['screen_lock', '{"minutes":5.0,"requirePassword":true}'], ['screen_lock', '{"minutes":5e0,"requirePassword":true}'],
  ['screen_lock', '{"minutes":5.00000000000000001,"requirePassword":true}'],
  ['screen_lock', '{"minutes":5,"minutes":10,"requirePassword":true}'],
  ['screen_lock', '{"minutes":5,"min\\u0075tes":10,"requirePassword":true}'],
  ['screen_lock', '[]'], ['screen_lock', 'null'], ['screen_lock', '{broken'],
  ['filevault', '{"enabled":"true"}'], ['filevault', '{"enabled":true,"secretRef":"fake-vault"}'],
  ['software_update', '{"automatic":true,"deferralDays":366}'], ['software_update', '{"automatic":true,"deferralDays":-1}'],
  ['software_update', '{"automatic":true,"deferralDays":1.5}'], ['software_update', '{"automatic":true,"deferralDays":null}'],
])('rejects unsupported, ambiguous or secret-bearing %s payload %#', (type, payload) => { reject(() => payloadValues(type, payload)); });
test.each([
  { name: ' Not trimmed' }, { description: 'trailing ' }, { name: '' }, { name: 'x'.repeat(161) }, { description: 'x'.repeat(2001) },
  { name: 'Control\u0080' }, { description: 'No\ncontrols' }, { platform: 'ios' }, { tenantId }, { permissions: [...COMPANY_BLUEPRINT_PERMISSIONS] },
  { configurations: Array.from({ length: 26 }, () => draft().configurations[0]) },
  { appPoolIds: Array.from({ length: 26 }, () => randomUUID()) },
  { appPoolIds: [blueprintId, blueprintId] }, { appPoolIds: ['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'] },
])('rejects out-of-contract draft fields %#', changes => { reject(() => draftValues({ ...draft(), ...changes })); });
test('configuration identifiers are unique within the draft and no other domain target can be smuggled into an item', () => {
  const value = draft(); value.configurations.push({ ...value.configurations[0] }); reject(() => draftValues(value));
  reject(() => draftValues({ ...draft(), configurations: [{ ...draft().configurations[0], targetUserId: userId }] }));
});
test('configuration limits count original UTF-8 payload bytes, not parsed values or JavaScript characters', () => {
  const payload = draft().configurations[0].payloadJson; const padded = ' '.repeat(65536 - Buffer.byteLength(payload)) + payload;
  const input = { ...draft(), configurations: Array.from({ length: 4 }, () => ({ ...draft().configurations[0], payloadJson: padded })) };
  expect(draftValues(input).configurations).toHaveLength(4); input.configurations.push({ ...draft().configurations[0], payloadJson: padded }); reject(() => draftValues(input));
  reject(() => payloadValues('screen_lock', ' ' + padded));
});
test.each([
  { confirm: false }, { confirm: 'true' }, { reason: 'short' }, { reason: 'x'.repeat(501) }, { reason: '  explicit reason  ' },
  { reason: 'Forbidden\nreason text' }, { tenantId }, { permissions: ['admin'] }, { id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' },
])('requires exact acknowledged creation intent %#', changes => { reject(() => writeValues('created', { ...write(), ...changes })); });
test('publish and restore cannot smuggle new desired values or silently turn a historical version into the current head', () => {
  expect(writeValues('published', { reason: 'Explicit local immutable version', confirm: true })).toEqual({ reason: 'Explicit local immutable version', confirm: true });
  reject(() => writeValues('published', { reason: 'Explicit local immutable version', confirm: true, draft: draft() }));
  reject(() => writeValues('restored', { reason: 'Explicit local draft restoration', confirm: true, version: '1' }));
  expect(writeValues('restored', { reason: 'Explicit local draft restoration', confirm: true, version: 1 }).version).toBe(1);
});
test('command shape preserves the original operation and captured revision without a cross-domain actor or tenant selector', () => {
  const value = { id: randomUUID(), correlationId: randomUUID(), blueprintId, action: 'created', expectedRevision: '0', reason: 'Exact original local operation', draft: draft(), version: null };
  expect(commandValues(value)).toEqual(value); reject(() => commandValues({ ...value, targetUserId: userId }));
  reject(() => commandValues({ ...value, expectedRevision: '1' })); reject(() => commandValues({ ...value, action: 'updated', expectedRevision: '0' }));
  reject(() => commandValues({ ...value, action: 'published', expectedRevision: '1' }));
});
test('strong ETags retain exact PostgreSQL int8 revisions and do not accept wildcard or another resource', () => {
  const header = etag({ id: blueprintId, revision: '9223372036854775807' });
  expect(expectedRevision(blueprintId, header)).toBe('9223372036854775807');
  expect(() => expectedRevision(blueprintId)).toThrow(expect.objectContaining({ status: 428 }));
  for (const invalid of ['*', 'W/' + header, etag({ id: randomUUID(), revision: '1' }), `"company-blueprint-${blueprintId}-01"`]) reject(() => expectedRevision(blueprintId, invalid));
});
test.each([{ tenantId }, { page: ['1'] }, { page: '0' }, { page: '01' }, { page: '1000001' }, { page: 1 }, { limit: '100' }, { search: ' secret ' }])('rejects ambiguous pagination/filter input %#', query => { reject(() => pagination(query, true)); });
test('pagination stays finite and only the list endpoint accepts an explicit search', () => {
  expect(pagination({})).toEqual({ page: 1, limit: 25, search: '' });
  expect(pagination({ page: '1000000', limit: '25', search: 'Baseline' }, true)).toEqual({ page: 1000000, limit: 25, search: 'Baseline' });
  reject(() => pagination({ search: '' }));
});
test('the new purpose-specific source is exact and remains independent from legacy Policy and License authority', () => {
  const user = actor(); const valid = source(user); expect(validSource(valid, user)).toBe(true);
  for (const changes of [{ target: null }, { companyBlueprintProtocol: 2 }, { permissions: ['policies.manage'] }, { permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'] }, { actorUserId: randomUUID() }, { tokenId: 'other-token' }, { expiresAt: user.exp + 1 }, { validUntil: user.auth_time + 301 }, { validUntil: user.auth_time - 1 }, { subject: ' owner ' }]) expect(validSource({ ...valid, ...changes }, user)).toBe(false);
  expect(validSource(valid, { ...user, amr: ['pwd'], mfa_authorization: undefined })).toBe(false);
  expect(validSource(valid, { ...user, actor_type: 'service' })).toBe(false);
  expect(validSource({ ...valid, tenant: { ...valid.tenant, global: true } }, user)).toBe(false);
});
test('OpenAPI separates own immutable artifacts, historical idempotent receipts and private purpose-specific authority', () => {
  const document = require('../../scripts/company-blueprint-openapi').companyBlueprintOpenApi(); const schemas = document.components.schemas;
  const create = document.paths['/api/company-blueprints'].post;
  expect(create.parameters.map(parameter => parameter.name)).toEqual(['Idempotency-Key']);
  expect(create.requestBody.content['application/json'].schema.additionalProperties).toBe(false);
  expect(document.paths['/api/company-blueprints/{id}/publish'].post.parameters.map(parameter => parameter.name)).toEqual(['id', 'Idempotency-Key', 'If-Match']);
  expect(document.paths['/api/company-blueprints/{id}/restore'].post.requestBody.content['application/json'].schema.properties.version.minimum).toBe(1);
  expect(Object.keys(schemas.CompanyBlueprintSource.properties)).toHaveLength(11);
  expect(schemas.CompanyBlueprintSource.properties.permissions.const).toEqual([...COMPANY_BLUEPRINT_PERMISSIONS]);
  expect(schemas.CompanyBlueprintDraft.properties.configurations.items.properties.type.enum).toEqual(['screen_lock', 'filevault', 'software_update']);
  expect(schemas.CompanyBlueprintSummary.properties.createdAt.format).toBe('date-time'); expect(schemas.CompanyBlueprintSummary.properties.createdAtISO).toBeUndefined();
  expect(schemas.CompanyBlueprintReceipt.properties.outcome.enum).toEqual(['applied', 'already_applied']);
  expect(schemas.CompanyBlueprintVersion.properties.apps.description).toContain('not a validity lease');
  expect(schemas.CompanyBlueprintEvent.properties.version.const).toBe(1);
});
