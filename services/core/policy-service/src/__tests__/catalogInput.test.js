'use strict';
const { parseCatalogInput } = require('../licenses/catalogInput');

test('normalizes catalog values while preserving a free price and explicit cleared fields', () => {
  expect(parseCatalogInput({ name: ' Suite ', cost_per_seat: 0, currency: 'chf', renewal_date: '', description: ' ', auto_approve: false }))
    .toEqual({ name: 'Suite', cost_per_seat: 0, currency: 'CHF', renewal_date: null, description: null, auto_approve: false });
  expect(parseCatalogInput({ renewal_date: null, cost_per_seat: null }, true)).toEqual({ renewal_date: null, cost_per_seat: null });
  expect(parseCatalogInput({ renewal_date: '2028-02-29' }, true).renewal_date).toBe('2028-02-29');
});
test.each([{ name: '' }, { name: {} }, { name: 'x'.repeat(161) }, { name: 'Suite', total_seats: -1 }, { name: 'Suite', total_seats: 1.5 },
  { name: 'Suite', cost_per_seat: -1 }, { name: 'Suite', cost_per_seat: '12' }, { name: 'Suite', cost_per_seat: 1.001 }, { name: 'Suite', cost_per_seat: Infinity },
  { name: 'Suite', currency: 'francs' }, { name: 'Suite', renewal_date: '2026-02-30' }, { name: 'Suite', renewal_date: '0000-01-01' },
  { name: 'Suite', auto_approve: 'false' }, { name: 'Suite', license_type: 'invented' }, { name: 'Suite', roles: ['admin'] }])('invalid catalog data is denied before SQL: %j', value => {
  expect(() => parseCatalogInput(value)).toThrow();
});
test('partial updates preserve omitted properties and validate private inventory data', () => {
  expect(parseCatalogInput({ total_seats: 12 }, true)).toEqual({ total_seats: 12 });
  expect(() => parseCatalogInput({}, true)).toThrow();
  expect(() => parseCatalogInput({ inventory_details: { password: 'secret' } }, true)).toThrow();
});
