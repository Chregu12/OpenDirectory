'use strict';

const { randomUUID } = require('node:crypto');
const { ouEtag, validateOuEtag, ouFields, validateOuTree } = require('../OuMutator');
const root = randomUUID(); const child = randomUUID(); const other = randomUUID(); const rows = [{ id: root, parent_id: null }, { id: child, parent_id: root }, { id: other, parent_id: null }];
test('OU versions retain exact BIGINT strings instead of rounding through JavaScript numbers', () => {
  const etag = ouEtag({ id: root, revision: '9223372036854775807' }); expect(etag).toBe(`"ou-${root}-9223372036854775807"`); expect(() => validateOuEtag(etag)).not.toThrow();
});
test.each([undefined, '*', `W/"ou-${root}-1"`, `"ou-${root}-0"`, `"ou-${root}-9223372036854775808"`, `"ou-${root}-1"\n`])('weak, missing or out-of-range OU version is rejected: %s', value => {
  expect(() => validateOuEtag(value)).toThrow(); try { validateOuEtag(value); } catch (error) { expect(error.status).toBe(value === undefined ? 428 : 400); }
});
test('an OU patch normalizes only exact metadata fields and canonical parent UUIDs', () => {
  expect(ouFields({ name: ' Engineering ', description: '  Real description\nsecond line ', parentId: root.toUpperCase() })).toEqual({ name: 'Engineering', description: 'Real description\nsecond line', parentId: root });
  expect(ouFields({ parentId: null })).toEqual({ parentId: null }); expect(ouFields({ description: null })).toEqual({ description: null });
});
test.each([{}, [], { name: '' }, { name: 'bad\nname' }, { name: 'Real', tenantId: randomUUID() }, { revision: '2' }, { parentId: 'alias' }, { parentId: undefined }, { description: 'x'.repeat(2001) }])('invalid or authority-widening OU patch cannot be silently ignored: %j', value => {
  expect(() => ouFields(value)).toThrow();
});
test('an existing subtree can move only under a known own parent', () => {
  expect(() => validateOuTree(rows, child, 'update', other)).not.toThrow(); expect(() => validateOuTree(rows, child, 'update', null)).not.toThrow();
  try { validateOuTree(rows, child, 'update', randomUUID()); } catch (error) { expect(error.status).toBe(404); }
});
test('self-parent and descendant-parent edits cannot create an OU cycle', () => {
  for (const parent of [root, child]) expect(() => validateOuTree(rows, root, 'update', parent)).toThrow();
});
test('only a leaf can retire and missing targets do not borrow an arbitrary tree', () => {
  expect(() => validateOuTree(rows, child, 'delete')).not.toThrow(); expect(() => validateOuTree(rows, root, 'delete')).toThrow(); expect(() => validateOuTree(rows, randomUUID(), 'delete')).toThrow();
});
test('depth checks include every descendant, not only the moved root', () => {
  const chain = Array.from({ length: 257 }, (_, index) => ({ id: String(index), parent_id: index === 0 || index === 255 ? null : String(index - 1) }));
  expect(() => validateOuTree(chain, '255', 'update', '254')).toThrow(); expect(() => validateOuTree(chain, '255', 'update', '253')).not.toThrow();
});
test('unresolved legacy parents and oversized collections fail closed', () => {
  expect(() => validateOuTree([...rows, { id: randomUUID(), parent_id: randomUUID() }], child, 'update', other)).toThrow(); expect(() => validateOuTree(Array.from({ length: 10001 }, () => ({ id: randomUUID(), parent_id: null })), root, 'delete')).toThrow();
});
