import { inventoryCsv, License, renewalStatus } from '@/lib/licenseInventory';
const now = new Date(2026, 10, 8, 15);
test.each([['2026-11-07', 'overdue'], ['2026-11-08', 'soon'], ['2026-12-08', 'soon'], ['2026-12-09', 'later'], [null, 'none'], ['', 'none'], ['invalid', 'none'], ['2026-02-30', 'none']])('calendar renewal status for %s is %s', (value, expected) => {
  expect(renewalStatus(value, now)).toBe(expected);
});
const license: License = { id: 'pool', name: '=FORMULA()', vendor: 'Vendor; "Name"', category: 'Software', license_type: 'per_user', total_seats: 0,
  used_seats: 3, cost_per_seat: '12.50', currency: 'EUR', auto_approve: false, created_at: '', renewal_date: '2026-11-07',
  inventory_details: { reference: ' @COMMAND', supplier: 'Supplier' }, description: 'Line 1\nLine 2' };
test('CSV retains procurement data and currencies, escapes delimiters and protects formula cells', () => {
  const result = inventoryCsv([license], now);
  expect(result).toMatch(/^\uFEFF/);
  expect(result).toContain('"\'=FORMULA()"');
  expect(result).toContain('"\' @COMMAND"');
  expect(result).toContain('"Vendor; ""Name"""');
  expect(result).toContain('"Unbegrenzt";"3";"Unbegrenzt";"12.50";"EUR"');
  expect(result).toContain('"Erneuerung überfällig"');
  expect(result).toContain('"Line 1\nLine 2"');
});
