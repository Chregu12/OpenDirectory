import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import AppsBooksView from '@/components/views/AppsBooksView';

const originalFetch = global.fetch;
const license = (changes = {}) => ({ id: 'actual-app', name: 'Actual Editor', platform: 'macOS', licenses: 10, assigned: 4, ...changes });
const response = (data: unknown) => ({ ok: true, json: async () => data });
const summary = (label: string) => screen.getByText(label).nextElementSibling;

beforeEach(() => { global.fetch = jest.fn(); });
afterAll(() => { global.fetch = originalFetch; });

test.each([
  ['array', (rows: unknown[]) => rows],
  ['apps envelope', (rows: unknown[]) => ({ apps: rows })],
  ['items envelope', (rows: unknown[]) => ({ items: rows })],
])('renders only actual license stock from an %s', async (_label, envelope) => {
  (global.fetch as jest.Mock).mockResolvedValue(response(envelope([license()])));
  render(<AppsBooksView />);
  const row = within(await screen.findByRole('row', { name: /Actual Editor/ }));
  expect(row.getAllByRole('cell').map(cell => cell.textContent)).toEqual(['Actual Editor', 'macOS', '10', '440%', '6', '—', '—']);
  expect(summary('TOTAL LICENSES')).toHaveTextContent('10');
  expect(summary('ASSIGNED')).toHaveTextContent('4');
  expect(summary('AVAILABLE')).toHaveTextContent('6');
  expect(global.fetch).toHaveBeenCalledWith('/api/apps?type=vpp');
  expect(screen.queryByText('Microsoft 365')).not.toBeInTheDocument();
});

test('uses total/used aliases and preserves a trusted explicit zero availability', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response({ apps: [
    { id: 0, title: 'Actual Editor', totalLicenses: 10, usedLicenses: 4, available: 0, expiryDate: 'N/A' },
  ] }));
  render(<AppsBooksView />);
  const row = within(await screen.findByRole('row', { name: /Actual Editor/ }));
  expect(row.getAllByRole('cell')[4]).toHaveTextContent(/^0$/);
  expect(summary('AVAILABLE')).toHaveTextContent(/^0$/);
  expect(summary('TOTAL LICENSES')).toHaveTextContent('10');
  expect(row.getAllByRole('cell')[1]).toHaveTextContent('—');
});

test('derives alias availability and gives primary zero counts precedence', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response([
    { id: 'alias-app', name: 'Alias Editor', totalLicenses: 7, usedLicenses: 2, available: null },
    license({ licenses: 0, totalLicenses: 10, assigned: 0, usedLicenses: 4 }),
  ]));
  render(<AppsBooksView />);
  await screen.findByText('Alias Editor');
  expect(summary('TOTAL LICENSES')).toHaveTextContent(/^7$/);
  expect(summary('ASSIGNED')).toHaveTextContent(/^2$/);
  expect(summary('AVAILABLE')).toHaveTextContent(/^5$/);
  const zeroRow = within(screen.getByRole('row', { name: /Actual Editor/ }));
  expect(zeroRow.getAllByRole('cell')[4]).toHaveTextContent(/^0$/);
});

test.each([[], { apps: [] }, { items: [] }])('keeps a real empty inventory empty: %j', async data => {
  (global.fetch as jest.Mock).mockResolvedValue(response(data));
  render(<AppsBooksView />);
  await screen.findByText('No apps found');
  expect(summary('TOTAL LICENSES')).toHaveTextContent(/^0$/);
  expect(summary('AVAILABLE')).toHaveTextContent(/^0$/);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test.each([
  ['missing totals', { licenses: undefined }],
  ['missing usage', { assigned: undefined }],
  ['numeric string total', { licenses: '10' }],
  ['numeric string usage', { assigned: '4' }],
  ['numeric string availability', { available: '6' }],
  ['NaN total', { licenses: NaN }],
  ['infinite total', { licenses: Infinity }],
  ['NaN usage', { assigned: NaN }],
  ['infinite availability', { available: Infinity }],
  ['NaN availability', { available: NaN }],
  ['negative total', { licenses: -1 }],
  ['negative usage', { assigned: -1 }],
  ['negative availability', { available: -1 }],
  ['fractional seats', { licenses: 10.5 }],
  ['unsafe seats', { licenses: Number.MAX_SAFE_INTEGER + 1 }],
  ['overassigned seats', { assigned: 11, available: 0 }],
  ['availability exceeds remaining seats', { available: 7 }],
  ['missing identity', { id: undefined }],
  ['blank identity', { id: ' ' }],
  ['missing name', { name: undefined }],
  ['object platform', { platform: {} }],
  ['object price', { price: {} }],
  ['object expiry', { expires: {} }],
])('rejects %s without manufacturing any stock', async (_label, changes) => {
  (global.fetch as jest.Mock).mockResolvedValue(response([license(changes)]));
  render(<AppsBooksView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('License inventory is unavailable');
  expect(summary('TOTAL LICENSES')).toHaveTextContent(/^—$/);
  expect(summary('ASSIGNED')).toHaveTextContent(/^—$/);
  expect(summary('AVAILABLE')).toHaveTextContent(/^—$/);
  expect(screen.queryByText('Actual Editor')).not.toBeInTheDocument();
  expect(screen.queryByText('Microsoft 365')).not.toBeInTheDocument();
  expect(screen.queryByText(/NaN|Infinity/)).not.toBeInTheDocument();
});

test.each([null, {}, { apps: {} }, { items: 'bad' }, { success: false, apps: [] }, [null], [42], [[]]])(
  'rejects malformed response %j instead of treating it as empty stock', async data => {
    (global.fetch as jest.Mock).mockResolvedValue(response(data));
    render(<AppsBooksView />);
    await screen.findByRole('alert');
    expect(screen.queryByText('No apps found')).not.toBeInTheDocument();
  },
);

test.each([
  ['duplicate identities', [license(), license()]],
  ['a malformed row alongside a valid row', [license(), null]],
  ['unsafe aggregate counts', [license({ licenses: Number.MAX_SAFE_INTEGER, assigned: 0 }), license({ id: 'second-app', assigned: 0 })]],
])('rejects %s instead of reporting misleading partial totals', async (_label, rows) => {
  (global.fetch as jest.Mock).mockResolvedValue(response(rows));
  render(<AppsBooksView />);
  await screen.findByRole('alert');
  expect(summary('AVAILABLE')).toHaveTextContent(/^—$/);
  expect(screen.queryByText('Actual Editor')).not.toBeInTheDocument();
});

test.each([401, 403, 503])('shows unavailable on HTTP %s', async status => {
  (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status });
  render(<AppsBooksView />);
  await screen.findByRole('alert');
  expect(summary('AVAILABLE')).toHaveTextContent(/^—$/);
});

test.each(['network', 'JSON'])('shows unavailable on %s failure', async failure => {
  const fetchMock = global.fetch as jest.Mock;
  if (failure === 'network') fetchMock.mockRejectedValue(new Error('offline'));
  else fetchMock.mockResolvedValue({ ok: true, json: async () => { throw new SyntaxError('Invalid JSON'); } });
  render(<AppsBooksView />);
  await screen.findByRole('alert');
  expect(summary('AVAILABLE')).toHaveTextContent(/^—$/);
});

test('clears stale stock on failed refresh and recovers to a real empty response', async () => {
  (global.fetch as jest.Mock).mockResolvedValueOnce(response([license()]))
    .mockResolvedValueOnce({ ok: false, status: 503 }).mockResolvedValueOnce(response([]));
  render(<AppsBooksView />);
  await screen.findByText('Actual Editor');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByRole('alert');
  expect(screen.queryByText('Actual Editor')).not.toBeInTheDocument();
  expect(summary('AVAILABLE')).toHaveTextContent(/^—$/);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByText('No apps found');
  expect(summary('AVAILABLE')).toHaveTextContent(/^0$/);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
