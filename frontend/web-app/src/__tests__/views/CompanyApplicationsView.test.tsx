import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyApplicationsView from '@/components/views/CompanyApplicationsView';
import { api } from '@/lib/api';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), patch: jest.fn() } }));

const actorId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const poolId = '33333333-3333-4333-8333-333333333333';
const userId = '44444444-4444-4444-8444-444444444444';
const assignmentId = '55555555-5555-4555-8555-555555555555';
const otherId = '66666666-6666-4666-8666-666666666666';
const base = '/api/licenses/company';
const timestamp = '2026-10-19T10:00:00.000Z';
const pool = (changes = {}) => ({ id: poolId, tenantId, revision: '1', name: 'Own Company Editor', vendor: 'Own Vendor', description: 'Actual local stock',
  totalSeats: 2, usedSeats: 0, availableSeats: 2, licenseType: 'per_user', allocationMode: 'local-only', createdAt: timestamp, updatedAt: timestamp, ...changes });
const identifier = (value: number) => '77777777-7777-4777-8777-' + String(value).padStart(12, '0');
const event = (version = 1) => ({ id: identifier(version), type: version === 1 ? 'app.license.pool.created' : version % 2 === 0 ? 'app.license.assigned' : 'app.license.released',
  version: 1, actorUserId: actorId, userId: version === 1 ? null : userId, correlationId: otherId, createdAt: timestamp,
  beforeRevision: version === 1 ? null : String(version - 1), afterRevision: String(version), deliveryStatus: 'pending' });
const assignment = () => ({ id: assignmentId, userId, assignedAt: timestamp, assignedBy: actorId, grantId: otherId });
const returnAssignments = (count = 1) => Array.from({ length: count }, (_, index) => ({ id: index === 0 ? assignmentId : identifier(index + 1000),
  poolId: index === 0 ? poolId : identifier(index + 2000), poolRevision: '9007199254740993', name: index === 0 ? 'Own Company Editor' : 'Return App ' + (index + 1),
  vendor: 'Own Vendor', grantId: identifier(index + 3000), assignedAt: timestamp }));
let rows: any[];
let access: any;
let directory: any;
let assigned: any[];
let events: any[];
let users: any[];
let returnRows: any[];
let returnTarget: any;

async function getResponse(url: string, config?: any) {
  if (url === base + '/capabilities') return { status: 200, data: access };
  const page = config?.params?.page || 1;
  const pageEnvelope = { schemaVersion: 1, actorUserId: actorId, tenantId, page, limit: 25 };
  if (url === base + '/users/' + userId + '/license-returns') return { status: 200, data: { ...pageEnvelope, userId, target: returnTarget, assignments: returnRows.slice((page - 1) * 25, page * 25), total: returnRows.length } };
  if (url === base + '/pools') return { status: 200, data: { ...pageEnvelope, pools: rows.slice((page - 1) * 25, page * 25), total: rows.length } };
  if (url === base + '/pools/' + poolId) return { status: 200, data: rows[0], headers: { etag: '"company-pool-' + poolId + '-' + rows[0].revision + '"' } };
  if (url === base + '/pools/' + poolId + '/edit-capabilities') return { status: 200, data: {
    schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: actorId, tenantId, poolId, poolRevision: rows[0].revision,
  }, headers: { 'cache-control': 'no-store' } };
  if (url === base + '/pools/' + poolId + '/assignments') return { status: 200, data: { ...pageEnvelope, poolId, assignments: assigned.slice((page - 1) * 25, page * 25), total: assigned.length } };
  if (url === base + '/pools/' + poolId + '/history') return { status: 200, data: { ...pageEnvelope, poolId, events: events.slice((page - 1) * 25, page * 25), total: events.length } };
  if (url === '/api/identity/access') return { status: 200, data: directory };
  if (url === '/api/users') {
    if (!directory.permissions.includes('users.read')) throw new Error('Profile disclosure without authority');
    return { status: 200, data: { users: users.slice((page - 1) * 25, page * 25), total: users.length, page, limit: 25 } };
  }
  throw new Error('Unexpected contract endpoint: ' + url);
}
beforeEach(() => {
  window.sessionStorage.clear();
  jest.resetAllMocks(); rows = [pool()]; assigned = []; events = [event()]; users = [];
  returnRows = returnAssignments(); returnTarget = { enabled: false, deleted: false, eligibilityRevision: '9007199254740993' };
  access = { schemaVersion: 1, companyLicenseProtocol: 1, actorUserId: actorId, tenantId, permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], allocationMode: 'local-only', supportedTargets: ['user'] };
  directory = { subject: 'signed-human', userId: actorId, permissions: [], demoMode: false, directoryReadProtocol: 1 };
  (api.get as jest.Mock).mockImplementation(getResponse);
  (api.patch as jest.Mock).mockImplementation(async (_url: string, input: { name: string; vendor: string; description: string; totalSeats: number }) => {
    rows = [{ ...rows[0], name: input.name, vendor: input.vendor, description: input.description, totalSeats: input.totalSeats,
      availableSeats: input.totalSeats - rows[0].usedSeats, revision: String(BigInt(rows[0].revision) + BigInt(1)) }, ...rows.slice(1)];
    events = [...events, { ...event(Number(rows[0].revision)), type: 'app.license.pool.updated', userId: null }];
    return { status: 200, data: rows[0], headers: { etag: '"company-pool-' + poolId + '-' + rows[0].revision + '"' } };
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, input: any) => {
    if (url === base + '/users/' + userId + '/license-returns') {
      returnRows = returnRows.filter(row => !input.assignments.some((item: any) => item.assignmentId === row.id));
      return { status: 200, data: { schemaVersion: 1, actorUserId: actorId, tenantId, userId, correlationId: otherId,
        results: input.assignments.map((item: any) => ({ poolId: item.poolId, assignmentId: item.assignmentId, status: 'released', code: 200 })) } };
    }
    if (url === base + '/pools') {
      const created = pool({ id: otherId, name: input.name, vendor: input.vendor, description: input.description, totalSeats: input.totalSeats, availableSeats: input.totalSeats }); rows = [...rows, created];
      return { status: 201, data: created };
    }
    const revoke = url.endsWith('/revoke');
    rows = [pool({ ...rows[0], revision: String(BigInt(rows[0].revision) + BigInt(1)), usedSeats: revoke ? 0 : 1, availableSeats: revoke ? 2 : 1 })];
    assigned = revoke ? [] : [assignment()]; events = [...events, event(Number(rows[0].revision))];
    return { status: revoke ? 200 : 201, data: rows[0] };
  });
});
async function renderLegacy() {
  const result = render(<CompanyApplicationsView />);
  fireEvent.click(await screen.findByRole('button', { name: 'Bisherige Direktverwaltung' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Bisherige Direktverwaltung' })).toHaveAttribute('aria-pressed', 'true'));
  return result;
}
async function openPool() {
  await renderLegacy();
  fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByRole('article', { name: 'Lizenzpooldetails' });
  await screen.findByLabelText('Kanonische Benutzer-ID');
  await within(screen.getByRole('region', { name: 'Lizenzzuweisungen' })).findByText('Keine Lizenzzuweisungen vorhanden.');
}
function reason(value = 'Reviewed employee assignment') { fireEvent.change(screen.getByLabelText('Begründung'), { target: { value } }); }
async function startAssignment() {
  await openPool(); reason(); fireEvent.change(screen.getByLabelText('Kanonische Benutzer-ID'), { target: { value: userId } });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenz zuweisen' }));
  return within(screen.getByRole('alertdialog', { name: 'Lizenzzuweisung bestätigen' }));
}

test('shows real own-company stock, assignments and pending history, never fake provider controls', async () => {
  await openPool(); const details = within(screen.getByRole('article', { name: 'Lizenzpooldetails' }));
  expect(details.getByText(poolId)).toBeInTheDocument(); expect(details.getByText(tenantId)).toBeInTheDocument();
  await details.findByText('Lizenzpool erstellt'); expect(details.getByText('Ereigniszustellung ausstehend')).toBeInTheDocument();
  expect(screen.getByText(/Keine Cloud-Zuweisung, Installation/)).toBeInTheDocument();
  expect(screen.getByText(/Kontosperren geben diese lokalen Lizenzen noch nicht automatisch zurück\./)).toBeInTheDocument();
  expect(screen.getByText(/ausdrücklich freigegeben werden, auch bei gesperrten oder gelöschten Benutzern\./)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /install|sso|kaufen|löschen/i })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' })).toBeEnabled();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/edit-capabilities'))).toBe(false);
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
  expect(api.post).not.toHaveBeenCalled();
});
test('UUID fallback assignment and manual release require separate confirmation and exact revision', async () => {
  const dialog = await startAssignment(); expect(dialog.getByText(/Reviewed employee assignment/)).toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByText('Lokale Lizenzzuweisung gespeichert.');
  expect(api.post).toHaveBeenNthCalledWith(1, base + '/pools/' + poolId + '/assignments', { userId, reason: 'Reviewed employee assignment', confirm: true }, { headers: { 'If-Match': '"company-pool-' + poolId + '-1"' }, signal: expect.any(AbortSignal) });
  reason('Manual reclaim of inactive user');
  const release = await screen.findByRole('button', { name: 'Lizenz freigeben' });
  fireEvent.click(release); expect(api.post).toHaveBeenCalledTimes(1);
  fireEvent.click(within(screen.getByRole('alertdialog', { name: 'Lizenzfreigabe bestätigen' })).getByRole('button', { name: 'Bestätigen' }));
  await screen.findByText('Lokale Lizenzzuweisung freigegeben.');
  expect(api.post).toHaveBeenNthCalledWith(2, base + '/pools/' + poolId + '/assignments/' + assignmentId + '/revoke', { userId, reason: 'Manual reclaim of inactive user', confirm: true }, { headers: { 'If-Match': '"company-pool-' + poolId + '-2"' }, signal: expect.any(AbortSignal) });
  await within(screen.getByRole('region', { name: 'Lizenzzuweisungen' })).findByText('Keine Lizenzzuweisungen vorhanden.');
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test('cancel never writes', async () => {
  const dialog = await startAssignment(); fireEvent.click(dialog.getByRole('button', { name: 'Abbrechen' }));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('creates a real normalized pool, with required reason and no edit/delete decoration', async () => {
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Lizenzpool erstellen' }));
  const dialog = within(screen.getByRole('alertdialog', { name: 'Lizenzpool erstellen' }));
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); expect(dialog.getByRole('alert')).toHaveTextContent(/Bitte Name/); expect(api.post).not.toHaveBeenCalled();
  for (const [label, value] of [['Anwendungsname', '  Planning App  '], ['Hersteller', '  Vendor  '], ['Beschreibung', 'Local stock'], ['Begründung', 'Reviewed company license purchase'], ['Lizenzanzahl', '10']]) {
    fireEvent.change(dialog.getByLabelText(label), { target: { value } });
  }
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByText('Lokaler Lizenzpool Planning App erstellt.');
  await screen.findByRole('button', { name: 'Planning App' });
  expect(api.post).toHaveBeenCalledWith(base + '/pools', { name: 'Planning App', vendor: 'Vendor', description: 'Local stock', totalSeats: 10, reason: 'Reviewed company license purchase' }, { signal: expect.any(AbortSignal) });
});
test.each([401, 403, 409, 412, 428, 503])('native %s clears private data and requires explicit reload, not a retry', async status => {
  const dialog = await startAssignment(); (api.post as jest.Mock).mockRejectedValue({ response: { status } });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/neu laden/);
  expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Own Company Editor' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Neu laden' }));
  await screen.findByRole('button', { name: 'Own Company Editor' }); expect(api.post).toHaveBeenCalledTimes(1);
});
test('read-only capabilities expose no creation, allocation, profile picker or revoke control', async () => {
  access.permissions = ['company.apps.read']; assigned = [assignment()]; await renderLegacy();
  fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByRole('article', { name: 'Lizenzpooldetails' });
  expect(screen.queryByRole('button', { name: 'Lizenzpool erstellen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Lizenz zuweisen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Lizenz freigeben' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/identity/access')).toBe(false);
});
test('no read capability produces a truthful empty permission state without fetching pools', async () => {
  access.permissions = []; render(<CompanyApplicationsView />); await screen.findByText('Keine Berechtigung zum Lesen der Firmen-Lizenzpools.');
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.post).not.toHaveBeenCalled();
});
test('active own directory users are offered only with independent profile-read authority', async () => {
  directory.permissions = ['users.read']; users = [{ id: userId, username: 'member', displayName: 'Active Employee', email: 'member@example.test', enabled: true, revision: '1', createdAt: timestamp }];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  const picker = await screen.findByRole('combobox', { name: 'Benutzer auswählen' });
  expect(within(picker).getByRole('option', { name: 'Active Employee · member' })).toBeInTheDocument();
  expect(screen.queryByLabelText('Kanonische Benutzer-ID')).not.toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith('/api/users', { params: { page: 1, limit: 25, enabled: 'true' }, signal: expect.any(AbortSignal) });
  reason(); fireEvent.change(picker, { target: { value: userId } }); fireEvent.click(screen.getByRole('button', { name: 'Lizenz zuweisen' }));
  expect(screen.getByRole('alertdialog')).toHaveTextContent(userId); expect(api.post).not.toHaveBeenCalled();
});
test('the assignment table reuses an authorized cached name, localizes its date and keeps exact IDs in a native disclosure', async () => {
  directory.permissions = ['users.read']; rows = [pool({ usedSeats: 1, availableSeats: 1 })]; assigned = [assignment()];
  users = [{ id: userId, username: 'member', displayName: 'Active Employee', email: 'member@example.test', enabled: true, revision: '1', createdAt: timestamp }];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByRole('combobox', { name: 'Benutzer auswählen' });
  const section = within(screen.getByRole('region', { name: 'Lizenzzuweisungen' }));
  expect(await section.findByRole('cell', { name: 'Active Employee' })).toBeInTheDocument();
  const formattedDate = new Date(timestamp).toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' });
  expect(section.getByText(formattedDate)).toHaveAttribute('datetime', timestamp); expect(section.queryByText(timestamp)).not.toBeInTheDocument();
  expect(section.queryByRole('columnheader', { name: 'Grant-ID' })).not.toBeInTheDocument();
  expect(section.queryByRole('columnheader', { name: 'Ausgeführt von' })).not.toBeInTheDocument();
  const summary = section.getByText('Nachweis', { selector: 'summary' }); const proof = summary.closest('details');
  expect(proof).not.toHaveAttribute('open');
  for (const identifier of [userId, actorId, otherId, assignmentId]) expect(within(proof).getByText(identifier)).not.toBeVisible();
  const profileRequests = (api.get as jest.Mock).mock.calls.filter(([url]) => url.startsWith('/api/users'));
  fireEvent.click(summary); expect(proof).toHaveAttribute('open');
  for (const identifier of [userId, actorId, otherId, assignmentId]) expect(within(proof).getByText(identifier)).toBeVisible();
  expect((api.get as jest.Mock).mock.calls.filter(([url]) => url.startsWith('/api/users'))).toEqual(profileRequests);
  expect(profileRequests).toHaveLength(1); expect(profileRequests[0][0]).toBe('/api/users');
});
test('a recipient absent from the authorized current directory page keeps its full UUID without profile lookups', async () => {
  directory.permissions = ['users.read']; rows = [pool({ usedSeats: 1, availableSeats: 1 })]; assigned = [assignment()];
  users = [{ id: otherId, username: 'another-member', displayName: 'Another Employee', email: 'another@example.test', enabled: true, revision: '1', createdAt: timestamp }];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' })); await screen.findByRole('combobox', { name: 'Benutzer auswählen' });
  const section = within(screen.getByRole('region', { name: 'Lizenzzuweisungen' }));
  expect(await section.findByRole('cell', { name: userId })).toBeInTheDocument();
  expect(section.queryByRole('cell', { name: 'Another Employee' })).not.toBeInTheDocument();
  const profileRequests = (api.get as jest.Mock).mock.calls.filter(([url]) => url.startsWith('/api/users'));
  expect(profileRequests).toHaveLength(1); expect(profileRequests[0][0]).toBe('/api/users');
});
test('without separate profile-read authority, assignments retain a full UUID and never discover a name', async () => {
  rows = [pool({ usedSeats: 1, availableSeats: 1 })]; assigned = [assignment()];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' })); await screen.findByLabelText('Kanonische Benutzer-ID');
  const section = within(screen.getByRole('region', { name: 'Lizenzzuweisungen' })); expect(await section.findByRole('cell', { name: userId })).toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.startsWith('/api/users'))).toBe(false);
});
test('full pools still permit explicit reclaim without requiring an active profile', async () => {
  rows = [pool({ usedSeats: 2, availableSeats: 0 })]; assigned = [assignment()];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByText(/Keine freien Lizenzen/); reason();
  const release = await screen.findByRole('button', { name: 'Lizenz freigeben' }); expect(release).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Lizenz zuweisen' })).toBeDisabled(); fireEvent.click(release);
  expect(screen.getByRole('alertdialog', { name: 'Lizenzfreigabe bestätigen' })).toHaveTextContent(userId);
});
test('pool list supports literal search and server pagination', async () => {
  rows = Array.from({ length: 26 }, (_, index) => pool({ id: index === 0 ? poolId : identifier(index), name: 'App ' + (index + 1) }));
  await renderLegacy(); await screen.findByRole('button', { name: 'App 1' });
  fireEvent.click(screen.getByRole('button', { name: 'Nächste Poolseite' })); await screen.findByRole('button', { name: 'App 26' });
  expect(screen.queryByRole('button', { name: 'App 1' })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Anwendungen suchen'), { target: { value: ' %_literal ' } }); fireEvent.click(screen.getByRole('button', { name: 'Suchen' }));
  await screen.findByRole('button', { name: 'App 1' });
  expect(api.get).toHaveBeenCalledWith(base + '/pools', { params: { page: 1, limit: 25, search: '%_literal' }, signal: expect.any(AbortSignal) });
});
test('empty backend results produce no fake apps', async () => {
  rows = []; await renderLegacy(); await screen.findByText('Keine Firmen-Lizenzpools gefunden.');
  expect(screen.queryByRole('button', { name: 'Own Company Editor' })).not.toBeInTheDocument();
});
test('assignment and history pagination use independently requested server pages', async () => {
  rows = [pool({ totalSeats: 30, usedSeats: 26, availableSeats: 4, revision: '27' })];
  assigned = Array.from({ length: 26 }, (_, index) => ({ ...assignment(), id: identifier(index + 100), userId: identifier(index + 200), grantId: identifier(index + 300) }));
  events = Array.from({ length: 27 }, (_, index) => event(index + 1));
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  const assignmentSection = within(await screen.findByRole('region', { name: 'Lizenzzuweisungen' }));
  await assignmentSection.findByRole('cell', { name: identifier(200) });
  fireEvent.click(assignmentSection.getByRole('button', { name: 'Nächste Zuweisungsseite' }));
  await assignmentSection.findByRole('cell', { name: identifier(225) }); expect(assignmentSection.queryByRole('cell', { name: identifier(200) })).not.toBeInTheDocument();
  const historySection = within(screen.getByRole('region', { name: 'Lizenzhistorie' }));
  await historySection.findByText('Lizenzpool erstellt');
  fireEvent.click(historySection.getByRole('button', { name: 'Nächste Historienseite' }));
  await historySection.findByText(/Version 26 → 27/); expect(historySection.queryByText('Lizenzpool erstellt')).not.toBeInTheDocument();
  for (const path of ['assignments', 'history']) expect(api.get).toHaveBeenCalledWith(base + '/pools/' + poolId + '/' + path, { params: { page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
});
test('session invalidation removes pool contents and a pending confirmation immediately', async () => {
  await startAssignment(); act(() => window.dispatchEvent(new Event('od:session-error')));
  expect(screen.getByRole('alert')).toHaveTextContent(/Sitzung/); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('foreign pool receipts never become visible', async () => {
  rows = [pool({ tenantId: otherId })]; render(<CompanyApplicationsView />);
  expect(await screen.findByRole('alert')).toHaveTextContent(/nicht bestätigt/); expect(screen.queryByRole('button', { name: 'Own Company Editor' })).not.toBeInTheDocument();
});
test('unknown company protocol stops before reading pools', async () => {
  access.companyLicenseProtocol = 0; render(<CompanyApplicationsView />);
  expect(await screen.findByRole('alert')).toHaveTextContent(/nicht bestätigt/); expect(api.get).toHaveBeenCalledTimes(1); expect(api.post).not.toHaveBeenCalled();
});
test('unmount aborts a pending write without confirming its late result', async () => {
  let resolve: (value: any) => void;
  const delayed = new Promise(complete => { resolve = complete; });
  const rendered = await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByLabelText('Kanonische Benutzer-ID'); reason(); fireEvent.change(screen.getByLabelText('Kanonische Benutzer-ID'), { target: { value: userId } }); fireEvent.click(screen.getByRole('button', { name: 'Lizenz zuweisen' }));
  (api.post as jest.Mock).mockReturnValue(delayed); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1)); const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  rendered.unmount(); expect(signal.aborted).toBe(true);
  await act(async () => resolve({ status: 201, data: pool({ revision: '2', usedSeats: 1, availableSeats: 1 }) }));
  expect(api.post).toHaveBeenCalledTimes(1);
});

async function openReturns() {
  const rendered = await renderLegacy(); await screen.findByRole('button', { name: 'Own Company Editor' });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben' }));
  fireEvent.change(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe'), { target: { value: userId } });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzrückgabe-Vorschau laden' }));
  await screen.findByRole('region', { name: 'Lizenzrückgabe-Vorschau' }); return rendered;
}
function beginReturns() {
  fireEvent.change(screen.getByLabelText('Begründung der Lizenzrückgabe'), { target: { value: 'Reviewed inactive employee licenses' } });
  fireEvent.click(screen.getByRole('button', { name: 'Diese Seite zurückgeben' }));
  return within(screen.getByRole('alertdialog', { name: 'Mitarbeiter-Lizenzrückgabe bestätigen' }));
}
test('return action requires explicit UUID preview, displays pool/vendor/version and never disables the identity', async () => {
  await renderLegacy(); await screen.findByRole('button', { name: 'Own Company Editor' });
  expect(screen.queryByLabelText('Mitarbeiter-ID für Lizenzrückgabe')).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.includes('/license-returns'))).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben' }));
  expect(screen.getByText(/Zuerst unter People → Konto sperren/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe'), { target: { value: userId } });
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.includes('/license-returns'))).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzrückgabe-Vorschau laden' }));
  const preview = within(await screen.findByRole('region', { name: 'Lizenzrückgabe-Vorschau' }));
  expect(preview.getByRole('cell', { name: 'Own Company Editor' })).toBeInTheDocument(); expect(preview.getByRole('cell', { name: 'Own Vendor' })).toBeInTheDocument();
  expect(preview.getByRole('cell', { name: '9007199254740993' })).toBeInTheDocument(); expect(preview.getByText(/1 Zuweisungen auf dieser Seite von 1 insgesamt/)).toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.startsWith('/api/users') || url === '/api/identity/access')).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test('an active employee remains previewable but cannot open a return confirmation', async () => {
  returnTarget.enabled = true; await openReturns(); expect(screen.getByText(/Aktiver Mitarbeiter: Rückgabe gesperrt/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Diese Seite zurückgeben' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Diese Seite zurückgeben' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('contradictory enabled and deleted target flags never expose a preview or return control', async () => {
  returnTarget = { enabled: true, deleted: true, eligibilityRevision: '2' };
  await renderLegacy(); await screen.findByRole('button', { name: 'Own Company Editor' });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben' }));
  fireEvent.change(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe'), { target: { value: userId } });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzrückgabe-Vorschau laden' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/nicht bestätigt/);
  expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Diese Seite zurückgeben' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('return reason validation and cancellation never write, and a changed UUID clears the preview', async () => {
  await openReturns(); fireEvent.click(screen.getByRole('button', { name: 'Diese Seite zurückgeben' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/Begründung mit 10 bis 500 Zeichen/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  const dialog = beginReturns(); expect(dialog.getByText(/Reviewed inactive employee licenses/)).toBeInTheDocument();
  expect(dialog.getByText(/Seite 1: genau 1 von insgesamt 1/)).toBeInTheDocument(); expect(dialog.getByText(/Own Company Editor.*Own Vendor.*9007199254740993/)).toBeInTheDocument();
  fireEvent.click(dialog.getByRole('button', { name: 'Abbrechen' })); expect(api.post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe'), { target: { value: otherId } });
  expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Diese Seite zurückgeben' })).not.toBeInTheDocument();
});
test('confirmed return sends exactly the displayed 25-item page once, reloads stock and clears old selections', async () => {
  returnRows = returnAssignments(26); await openReturns();
  fireEvent.click(screen.getByRole('button', { name: 'Own Company Editor' })); await screen.findByLabelText('Kanonische Benutzer-ID');
  const preview = within(screen.getByRole('region', { name: 'Lizenzrückgabe-Vorschau' }));
  expect(preview.getByText(/25 Zuweisungen auf dieser Seite von 26 insgesamt/)).toBeInTheDocument(); expect(preview.queryByText('Return App 26')).not.toBeInTheDocument();
  const dialog = beginReturns(); expect(api.post).not.toHaveBeenCalled(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); fireEvent.click(dialog.getByRole('button', { name: 'Wird ausgeführt …' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Lizenzrückgabe' }));
  expect(result.getByRole('status')).toHaveTextContent('25 von 25 Freigaben dieser Seite bestätigt · Seite 1 · zuvor 26 Zuweisungen insgesamt.');
  expect(result.getByText(/kein vollständiges Offboarding/)).toBeInTheDocument();
  const proof = result.getAllByText('Nachweis', { selector: 'summary' })[0].closest('details');
  expect(within(proof).getByText('Korrelations-ID').nextElementSibling).toHaveTextContent(otherId);
  await screen.findByRole('button', { name: 'Own Company Editor' }); expect(screen.queryByRole('article')).not.toBeInTheDocument();
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe')).toHaveValue('');
  expect(api.post).toHaveBeenCalledTimes(1); expect(api.post).toHaveBeenCalledWith(base + '/users/' + userId + '/license-returns', {
    reason: 'Reviewed inactive employee licenses', confirm: true,
    assignments: returnAssignments(25).map(row => ({ poolId: row.poolId, assignmentId: row.id, poolRevision: row.poolRevision })),
  }, { signal: expect.any(AbortSignal) });
  expect((api.get as jest.Mock).mock.calls.filter(([url]) => url.includes('/license-returns'))).toHaveLength(1); expect(returnRows).toHaveLength(1);
});
test('paging the preview explicitly selects only the current final page', async () => {
  returnRows = returnAssignments(26); await openReturns(); fireEvent.click(screen.getByRole('button', { name: 'Nächste Rückgabeseite' }));
  const preview = within(screen.getByRole('region', { name: 'Mitarbeiter-Lizenzrückgabe' })); await preview.findByRole('cell', { name: 'Return App 26' });
  expect(preview.getByText(/1 Zuweisungen auf dieser Seite von 26 insgesamt/)).toBeInTheDocument();
  fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('region', { name: 'Ergebnis der Lizenzrückgabe' });
  const last = returnAssignments(26)[25]; expect(api.post).toHaveBeenCalledWith(base + '/users/' + userId + '/license-returns', {
    reason: 'Reviewed inactive employee licenses', confirm: true, assignments: [{ poolId: last.poolId, assignmentId: last.id, poolRevision: last.poolRevision }],
  }, { signal: expect.any(AbortSignal) }); expect(api.post).toHaveBeenCalledTimes(1);
});
test('207 shows confirmed, unconfirmed and not-attempted outcomes with correlation, without asserting rollback or completion', async () => {
  returnRows = returnAssignments(3); await openReturns();
  (api.post as jest.Mock).mockImplementation(async (_url: string, input: any) => ({ status: 207, data: { schemaVersion: 1, actorUserId: actorId, tenantId, userId, correlationId: otherId,
    results: input.assignments.map((row: any, index: number) => ({ poolId: row.poolId, assignmentId: row.assignmentId, status: ['released', 'unconfirmed', 'not_attempted'][index], code: [200, 503, null][index] })) } }));
  fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Lizenzrückgabe' }));
  expect(result.getByRole('status')).toHaveTextContent('1 von 3 Freigaben dieser Seite bestätigt');
  for (const label of [/Freigabe bestätigt \(200\)/, /Ergebnis nicht bestätigt \(503\)/, /Nicht versucht/]) expect(result.getByText(label)).toBeInTheDocument();
  expect(result.getByText(/Unbestätigte Ergebnisse können bereits wirksam sein/)).toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
  expect((api.get as jest.Mock).mock.calls.filter(([url]) => url.includes('/license-returns'))).toHaveLength(1);
});
test('return receipts retain captured application names and vendors and disclose technical IDs only in native details', async () => {
  await openReturns(); returnRows[0] = { ...returnRows[0], name: 'Later application name', vendor: 'Later vendor' };
  fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Lizenzrückgabe' }));
  expect(result.getByText('Own Company Editor · Freigabe bestätigt (200)')).toBeVisible(); expect(result.getByText('Own Vendor')).toBeVisible();
  expect(result.queryByText(/Later application name|Later vendor/)).not.toBeInTheDocument();
  const summary = result.getByText('Nachweis', { selector: 'summary' }); const proof = summary.closest('details');
  expect(proof).not.toHaveAttribute('open');
  for (const identifier of [poolId, assignmentId, userId, otherId]) expect(result.getByText(identifier)).not.toBeVisible();
  const requests = (api.get as jest.Mock).mock.calls.map(([url]) => url);
  summary.focus(); expect(summary).toHaveFocus(); fireEvent.click(summary); expect(proof).toHaveAttribute('open');
  for (const identifier of [poolId, assignmentId, userId, otherId]) expect(within(proof).getByText(identifier)).toBeVisible();
  expect((api.get as jest.Mock).mock.calls.map(([url]) => url)).toEqual(requests);
  expect(requests.some(url => url.startsWith('/api/users') || url === '/api/identity/access')).toBe(false); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each(['actorUserId', 'tenantId'])('a successful receipt is hidden when post-write reload changes the current %s', async field => {
  await openReturns(); let afterWrite = 0; let switched = false;
  (api.get as jest.Mock).mockImplementation(async (url: string, config?: any) => {
    if (url === base + '/capabilities' && (api.post as jest.Mock).mock.calls.length > 0) {
      afterWrite += 1;
      if (afterWrite >= 2) { switched = true; return { status: 200, data: { ...access, [field]: otherId } }; }
    }
    if (switched && url === base + '/pools') return { status: 200, data: { schemaVersion: 1, actorUserId: field === 'actorUserId' ? otherId : actorId,
      tenantId: field === 'tenantId' ? otherId : tenantId, pools: [], total: 0, page: config.params.page, limit: 25 } };
    return getResponse(url, config);
  });
  fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' })); await screen.findByText('Keine Firmen-Lizenzpools gefunden.');
  expect(switched).toBe(true); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Ergebnis der Lizenzrückgabe' })).not.toBeInTheDocument();
  expect(screen.queryByText('Own Company Editor · Freigabe bestätigt (200)')).not.toBeInTheDocument();
  expect(screen.queryByText('Own Vendor')).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each([401, 403, 404, 409, 412, 428, 503])('return failure %s clears private snapshots and never retries after explicit reload', async status => {
  await openReturns(); (api.post as jest.Mock).mockRejectedValue({ response: { status } }); fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/neu laden/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Ergebnis der Lizenzrückgabe' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Neu laden' })); await screen.findByRole('button', { name: 'Own Company Editor' });
  expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByLabelText('Mitarbeiter-ID für Lizenzrückgabe')).toHaveValue('');
});
test('empty employee preview cannot return, including when the target is deleted', async () => {
  returnRows = []; returnTarget = { enabled: false, deleted: true, eligibilityRevision: '2' }; await openReturns();
  expect(screen.getByText('Keine lokalen Lizenzzuweisungen für diesen Mitarbeiter vorhanden.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Diese Seite zurückgeben' })).toBeDisabled(); expect(api.post).not.toHaveBeenCalled();
});
test('read-only users do not see the employee return action', async () => {
  access.permissions = ['company.apps.read']; await renderLegacy(); await screen.findByRole('button', { name: 'Own Company Editor' });
  expect(screen.queryByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben' })).not.toBeInTheDocument();
});
test('session invalidation clears a pending employee return confirmation immediately', async () => {
  await openReturns(); beginReturns(); act(() => window.dispatchEvent(new Event('od:session-error')));
  expect(screen.getByRole('alert')).toHaveTextContent(/Sitzung/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Lizenzrückgabe-Vorschau' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('unmount aborts an employee return write and discards its late successful receipt', async () => {
  const rendered = await openReturns(); let resolve: (value: any) => void;
  (api.post as jest.Mock).mockImplementation((_url: string, input: any) => new Promise(complete => { resolve = () => complete({ status: 200, data: {
    schemaVersion: 1, actorUserId: actorId, tenantId, userId, correlationId: otherId, results: input.assignments.map((row: any) => ({ poolId: row.poolId, assignmentId: row.assignmentId, status: 'released', code: 200 })),
  } }); }));
  fireEvent.click(beginReturns().getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  const signal = (api.post as jest.Mock).mock.calls[0][2].signal; rendered.unmount(); expect(signal.aborted).toBe(true);
  await act(async () => resolve(null)); expect(api.post).toHaveBeenCalledTimes(1);
});

async function openEdit() {
  await openPool(); fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  return within(await screen.findByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten' }));
}
function fillEdit(dialog: ReturnType<typeof within>) {
  for (const [label, value] of [['Anwendungsname', ' Updated Company Editor '], ['Hersteller', ' Updated Vendor '], ['Beschreibung', ' Updated local stock '], ['Lizenzanzahl', '3'], ['Begründung', ' Reviewed company license stock ']]) {
    fireEvent.change(dialog.getByLabelText(label), { target: { value } });
  }
}
function reviewEdit(dialog: ReturnType<typeof within>) {
  fillEdit(dialog); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  return within(screen.getByRole('alertdialog', { name: 'Änderungen an App und Lizenzbestand bestätigen' }));
}
test('editing is explicit, prefilled and cancelable at both stages without writing', async () => {
  const dialog = await openEdit();
  for (const [label, value] of [['Anwendungsname', 'Own Company Editor'], ['Hersteller', 'Own Vendor'], ['Beschreibung', 'Actual local stock']]) expect(dialog.getByLabelText(label)).toHaveValue(value);
  expect(dialog.getByLabelText('Lizenzanzahl')).toHaveValue(2); expect(dialog.getByLabelText('Begründung')).toHaveValue('');
  expect(dialog.getByText(/Kein Kauf, keine Abrechnung/)).toBeInTheDocument();
  fireEvent.click(dialog.getByRole('button', { name: 'Abbrechen' })); expect(api.patch).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  const next = within(await screen.findByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten' }));
  const review = reviewEdit(next);
  for (const label of ['Vorher', 'Nachher', 'Own Company Editor', 'Updated Company Editor', 'Own Vendor', 'Updated Vendor', 'Actual local stock', 'Updated local stock']) expect(review.getByText(label)).toBeInTheDocument();
  expect(review.getByText(/Bereits zugewiesen: 0. Mindestbestand: 1/)).toBeInTheDocument(); expect(api.patch).not.toHaveBeenCalled();
  fireEvent.click(review.getByRole('button', { name: 'Abbrechen' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(api.patch).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('edit validates reason, all fields, no-op and occupied-seat floor before review', async () => {
  rows = [pool({ totalSeats: 3, usedSeats: 2, availableSeats: 1 })]; assigned = [assignment()];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByLabelText('Kanonische Benutzer-ID'); fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  const dialog = within(await screen.findByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten' }));
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); expect(dialog.getByRole('alert')).toHaveTextContent(/Begründung/);
  fireEvent.change(dialog.getByLabelText('Begründung'), { target: { value: 'Reviewed company license stock' } });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); expect(dialog.getByRole('alert')).toHaveTextContent(/Keine Änderung/);
  fireEvent.change(dialog.getByLabelText('Lizenzanzahl'), { target: { value: '1' } });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); expect(dialog.getByRole('alert')).toHaveTextContent(/mindestens 2 bereits zugewiesene/);
  expect(dialog.getByLabelText('Lizenzanzahl')).toHaveValue(1); expect(dialog.getByLabelText('Lizenzanzahl')).toHaveAttribute('min', '2');
  fireEvent.change(dialog.getByLabelText('Lizenzanzahl'), { target: { value: '2' } });
  fireEvent.change(dialog.getByLabelText('Hersteller'), { target: { value: ' ' } });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); expect(dialog.getByRole('alert')).toHaveTextContent(/Bitte Name, Hersteller/);
  expect(api.patch).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('confirmed occupied pool edit refreshes real details, stock and history and uses only one PATCH', async () => {
  rows = [pool({ usedSeats: 1, availableSeats: 1 })];
  await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByLabelText('Kanonische Benutzer-ID'); fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  const dialog = within(await screen.findByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten' })); const review = reviewEdit(dialog);
  expect(review.getByText(/Bereits zugewiesen: 1. Mindestbestand: 1/)).toBeInTheDocument(); expect(api.patch).not.toHaveBeenCalled();
  const readsBefore = (api.get as jest.Mock).mock.calls.length;
  fireEvent.click(review.getByRole('button', { name: 'Bestätigen' })); fireEvent.click(review.getByRole('button', { name: 'Wird ausgeführt …' }));
  await screen.findByText('App und lokaler Lizenzbestand aktualisiert.');
  await screen.findByRole('button', { name: 'Updated Company Editor' });
  const details = within(await screen.findByRole('article', { name: 'Lizenzpooldetails' })); await details.findByText('App und Lizenzbestand aktualisiert');
  expect(details.getByRole('heading', { name: 'Updated Company Editor' })).toBeInTheDocument(); expect(details.getByText('Updated Vendor')).toBeInTheDocument();
  expect(details.getByText('Lizenzbestand').nextElementSibling).toHaveTextContent('3'); expect(details.getByText('Zugewiesen').nextElementSibling).toHaveTextContent('1');
  expect(details.getByText('Verfügbar').nextElementSibling).toHaveTextContent('2'); expect(details.getByText(/Version 1 → 2/)).toBeInTheDocument();
  expect(api.patch).toHaveBeenCalledTimes(1); expect(api.patch).toHaveBeenCalledWith(base + '/pools/' + poolId, {
    name: 'Updated Company Editor', vendor: 'Updated Vendor', description: 'Updated local stock', totalSeats: 3, reason: 'Reviewed company license stock', confirm: true,
  }, { headers: { 'If-Match': '"company-pool-' + poolId + '-1"' }, signal: expect.any(AbortSignal) });
  const reads = (api.get as jest.Mock).mock.calls.slice(readsBefore).map(([url]) => url);
  for (const path of ['/pools', '/pools/' + poolId, '/pools/' + poolId + '/history', '/pools/' + poolId + '/assignments']) expect(reads).toContain(base + path);
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('catalog refresh applies the active search, ordering and count after an edited pool stops matching', async () => {
  const remaining = pool({ id: otherId, name: 'Own B Editor' }); rows = [pool(), remaining];
  (api.get as jest.Mock).mockImplementation(async (url: string, config?: { params?: { page?: number; search?: string } }) => {
    if (url === base + '/pools') {
      const matching = rows.filter(row => !config?.params?.search || row.name.includes(config.params.search)).sort((first, second) => first.name.localeCompare(second.name));
      return { status: 200, data: { schemaVersion: 1, actorUserId: actorId, tenantId, pools: matching, total: matching.length, page: 1, limit: 25 } };
    }
    return getResponse(url, config);
  });
  await renderLegacy(); await screen.findByRole('button', { name: 'Own Company Editor' });
  fireEvent.change(screen.getByLabelText('Anwendungen suchen'), { target: { value: 'Own' } }); fireEvent.click(screen.getByRole('button', { name: 'Suchen' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' })); await screen.findByLabelText('Kanonische Benutzer-ID');
  fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  const review = reviewEdit(within(await screen.findByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten' })));
  fireEvent.click(review.getByRole('button', { name: 'Bestätigen' })); await screen.findByText('App und lokaler Lizenzbestand aktualisiert.');
  const catalogue = within(await screen.findByRole('region', { name: 'Firmen-Lizenzpools' }));
  await catalogue.findByRole('button', { name: 'Own B Editor' }); expect(catalogue.queryByRole('button', { name: 'Updated Company Editor' })).not.toBeInTheDocument();
  expect(catalogue.getByText('Seite 1 von 1 · 1 Einträge')).toBeInTheDocument(); expect(screen.getByLabelText('Anwendungen suchen')).toHaveValue('Own');
  expect(api.patch).toHaveBeenCalledTimes(1);
});
test.each([{ permissions: ['company.apps.read'] }, { permissions: ['company.apps.read', 'company.apps.assign'] }])('edit requires catalogue write authority: %j', async ({ permissions }) => {
  access.permissions = permissions; await renderLegacy(); fireEvent.click(await screen.findByRole('button', { name: 'Own Company Editor' }));
  await screen.findByRole('article', { name: 'Lizenzpooldetails' }); expect(screen.queryByRole('button', { name: 'App und Lizenzbestand bearbeiten' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/edit-capabilities'))).toBe(false); expect(api.patch).not.toHaveBeenCalled();
});
test.each(['missing', 'old protocol', 'foreign tenant', 'unsupported source'])('explicit edit refuses %s capability without a form or write', async scenario => {
  await openPool();
  (api.get as jest.Mock).mockImplementation(async (url: string, config?: unknown) => {
    if (url.endsWith('/edit-capabilities')) {
      if (scenario === 'missing') throw { response: { status: 404 } };
      if (scenario === 'unsupported source') throw { response: { status: 409 } };
      const response = await getResponse(url); return { ...response, data: { ...response.data, ...(scenario === 'old protocol' ? { companyPoolEditProtocol: 0 } : { tenantId: otherId }) } };
    }
    return getResponse(url, config);
  });
  fireEvent.click(screen.getByRole('button', { name: 'App und Lizenzbestand bearbeiten' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.patch).not.toHaveBeenCalled();
});
test.each([409, 412, 428, 'timeout', 'malformed', 'wrong ETag'])('lost or rejected edit %s requires readback and cannot be retried from the old confirmation', async scenario => {
  const review = reviewEdit(await openEdit());
  if (typeof scenario === 'number') (api.patch as jest.Mock).mockRejectedValue({ response: { status: scenario } });
  else if (scenario === 'timeout') (api.patch as jest.Mock).mockRejectedValue(new Error('timeout'));
  else (api.patch as jest.Mock).mockResolvedValue({ status: 200, data: scenario === 'malformed' ? { ...pool(), pending: true } : pool({ revision: '2' }), headers: { etag: '"wrong"' } });
  fireEvent.click(review.getByRole('button', { name: 'Bestätigen' })); expect(await screen.findByRole('alert')).toHaveTextContent(/neu laden/);
  expect(screen.getByRole('alert')).toHaveTextContent(/Nicht erneut bestätigen; zuerst den aktuellen Pool neu laden und prüfen/);
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('article')).not.toBeInTheDocument();
  expect(screen.queryByText('App und lokaler Lizenzbestand aktualisiert.')).not.toBeInTheDocument(); expect(api.patch).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Neu laden' })); await screen.findByRole('button', { name: 'Own Company Editor' }); expect(api.patch).toHaveBeenCalledTimes(1);
});
test.each(['review', 'pending write'])('session invalidation removes an edit at %s and never displays a late success', async phase => {
  const review = reviewEdit(await openEdit()); let resolve: (value: unknown) => void;
  if (phase === 'pending write') {
    (api.patch as jest.Mock).mockReturnValue(new Promise(complete => { resolve = complete; }));
    fireEvent.click(review.getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(api.patch).toHaveBeenCalledTimes(1));
  }
  act(() => window.dispatchEvent(new Event('od:session-error')));
  expect(screen.getByRole('alert')).toHaveTextContent(/Sitzung/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  if (phase === 'pending write') {
    expect((api.patch as jest.Mock).mock.calls[0][2].signal.aborted).toBe(true);
    await act(async () => resolve({ status: 200, data: pool({ revision: '2' }) }));
  }
  expect(screen.queryByText('App und lokaler Lizenzbestand aktualisiert.')).not.toBeInTheDocument(); expect(api.patch).toHaveBeenCalledTimes(phase === 'review' ? 0 : 1);
});
