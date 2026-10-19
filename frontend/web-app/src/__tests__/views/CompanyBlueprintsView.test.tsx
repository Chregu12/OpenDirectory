import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyBlueprintsView from '@/components/views/CompanyBlueprintsView';
import { api } from '@/lib/api';
import { CompanyApplicationsClient } from '@/lib/companyApplications';
import { CompanyBlueprintDetail, CompanyBlueprintDraft, companyBlueprintEtag } from '@/lib/companyBlueprints';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), put: jest.fn() } }));
const mock = api as jest.Mocked<typeof api>;
const base = '/api/company-blueprints';
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const now = '2026-10-19T12:00:00.000Z';
const access = () => ({ schemaVersion: 1, companyBlueprintProtocol: 1, actorUserId: id(90), tenantId: id(91),
  permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'], configurationMode: 'local-only', maxConfigurations: 25, maxApplications: 25 });
const draft = (): CompanyBlueprintDraft => ({ name: 'Arbeitsplatz', description: 'Sicherer Standard', platform: 'macos', configurations: [
  { id: id(10), type: 'screen_lock', name: 'Bildschirmsperre', payloadJson: '{"minutes":5,"requirePassword":true}' },
], appPoolIds: [id(20)] });
const detail = (): CompanyBlueprintDetail => ({ id: id(1), tenantId: id(91), revision: '3', publishedVersion: 1, draftChanged: true,
  draft: draft(), createdAt: now, updatedAt: now, preview: { configurationCount: 1, hasConflicts: false,
    effectiveConfigurations: [{ configType: 'screen_lock', payloadJson: '{"requirePassword":true,"minutes":5}', sources: [{ blueprintId: id(1), configurationId: id(10) }] }], conflicts: [] } });
const metadata = () => ({ version: 1, sourceRevision: '1', publishedRevision: '2', actorUserId: id(90), operationId: id(92), createdAt: now });
const audit = () => ({ id: id(93), tenantId: id(91), type: 'blueprint.published', version: 1, blueprintId: id(1), actorUserId: id(90), correlationId: id(94),
  createdAt: now, beforeRevision: '1', afterRevision: '2', releasedVersion: 1, restoredFrom: null, reason: 'Geprüfte lokale Freigabe', deliveryStatus: 'pending' });
const envelope = (fields = {}) => ({ schemaVersion: 1, actorUserId: id(90), tenantId: id(91), ...fields });
const ok = (data: unknown, headers = {}) => ({ status: 200, data, headers });
let accessData: ReturnType<typeof access>;
let detailData: CompanyBlueprintDetail;
let listRows: { id: string; name: string }[];
let snapshot: ReturnType<typeof metadata> & { draft: CompanyBlueprintDraft; apps: { id: string; name: string; vendor: string; revision: string }[] };
let sequence: number;
let appAccess: jest.SpyInstance;
let appList: jest.SpyInstance;
beforeEach(() => {
  jest.resetAllMocks(); accessData = access(); detailData = detail(); listRows = [{ id: id(1), name: 'Arbeitsplatz' }]; sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  snapshot = { ...metadata(), draft: { ...draft(), name: 'Historischer Arbeitsplatz' }, apps: [{ id: id(20), name: 'Historische Büro-App', vendor: 'Früherer Hersteller', revision: '99' }] };
  mock.get.mockImplementation(async (url, options) => {
    if (url === base + '/capabilities') return ok(accessData);
    if (url === base) {
      const page = options?.params?.page || 1;
      return ok(envelope({ total: listRows.length, page, limit: 25, blueprints: listRows.slice((page - 1) * 25, page * 25).map(row => ({ ...row,
        tenantId: id(91), platform: detailData.draft.platform, revision: detailData.revision, publishedVersion: detailData.publishedVersion,
        draftChanged: detailData.draftChanged, configurationCount: detailData.draft.configurations.length, appCount: detailData.draft.appPoolIds.length, createdAt: now, updatedAt: now })) }));
    }
    if (url === base + '/' + id(1)) return ok(envelope({ blueprint: detailData }), { etag: companyBlueprintEtag(detailData) });
    if (url.endsWith('/versions/1')) return ok(envelope({ blueprintId: id(1), version: snapshot }));
    if (url.endsWith('/versions')) return ok(envelope({ blueprintId: id(1), total: 1, page: options?.params?.page || 1, limit: 25, versions: [metadata()] }));
    if (url.endsWith('/history')) return ok(envelope({ blueprintId: id(1), total: 1, page: options?.params?.page || 1, limit: 25, events: [audit()] }));
    throw new Error('Unexpected read ' + url);
  });
  appAccess = jest.spyOn(CompanyApplicationsClient.prototype, 'reload').mockResolvedValue({ schemaVersion: 1, companyLicenseProtocol: 1,
    actorUserId: id(90), tenantId: id(91), permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], allocationMode: 'local-only', supportedTargets: ['user'] });
  appList = jest.spyOn(CompanyApplicationsClient.prototype, 'list').mockResolvedValue({ total: 1, page: 1, limit: 25, pools: [
    { id: id(20), tenantId: id(91), name: 'Büro-App', vendor: 'Hersteller', description: '', revision: '8', totalSeats: 10, usedSeats: 2, availableSeats: 8, licenseType: 'per_user', allocationMode: 'local-only', createdAt: now, updatedAt: now },
  ] });
});
afterEach(() => { appAccess.mockRestore(); appList.mockRestore(); });
async function mount() { const rendered = render(<CompanyBlueprintsView />); await screen.findByRole('region', { name: 'Blueprint-Katalog' }); return rendered; }
async function open() { await mount(); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsplatz' })); return screen.findByRole('region', { name: 'Blueprint-Details' }); }
async function edit() { await open(); fireEvent.click(screen.getByRole('button', { name: 'Entwurf bearbeiten' })); return screen.findByRole('region', { name: 'Blueprint-Editor' }); }
const reason = () => fireEvent.change(screen.getByLabelText('Begründung für die Änderung', { exact: true }), { target: { value: 'Bewusste neue lokale Konfiguration' } });
async function create() {
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Blueprint erstellen' }));
  fireEvent.change(screen.getByLabelText('Blueprint-Name'), { target: { value: 'Neuer Arbeitsplatz' } }); reason();
}
function prepareWrite(action: 'created' | 'updated' | 'published' | 'restored', outcome = 'applied') {
  const respond = async (_url: string, body: { id?: string }, options: { headers: Record<string, string> }) => ({ status: action === 'created' && outcome === 'applied' ? 201 : 200,
    data: envelope({ operationId: options.headers['Idempotency-Key'], blueprintId: body.id || id(1), revision: action === 'created' ? '1' : '4',
      publishedVersion: action === 'created' ? null : action === 'published' ? 2 : 1, action, outcome, deliveryStatus: 'pending' }) });
  mock.post.mockImplementation(respond); mock.put.mockImplementation(respond);
}
function approve() {
  const dialog = screen.getByRole('alertdialog'); fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diesen lokalen Blueprint-Vorgang.' }));
  fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
}
const postBody = () => mock.post.mock.calls[0][1] as { id: string; draft: CompanyBlueprintDraft };
const putBody = () => mock.put.mock.calls[0][1] as { draft: CompanyBlueprintDraft };
function deferred<Value>() {
  let resolve: (value: Value) => void;
  const promise = new Promise<Value>(accept => { resolve = accept; });
  return { promise, resolve: (value: Value) => resolve(value) };
}

test('shows real own-tenant data with no global-policy or license authority requests', async () => {
  await mount(); expect(screen.getByRole('heading', { name: 'Firmen-Blueprints' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Arbeitsplatz' })).toBeInTheDocument();
  expect(screen.getByText(/Keine Gerätezuweisung, Installation, Lizenzreservierung/)).toBeInTheDocument();
  expect(mock.get.mock.calls.every(([url]) => url.startsWith(base))).toBe(true); expect(appAccess).not.toHaveBeenCalled(); expect(mock.post).not.toHaveBeenCalled();
});
test('shows a true empty state rather than generated records', async () => {
  listRows = []; await mount(); expect(screen.getByText('Noch keine Firmen-Blueprints vorhanden.')).toBeInTheDocument();
});
test.each([401, 403, 428, 503])('initial source status %s shows no catalogue, editor or made-up buttons', async status => {
  mock.get.mockRejectedValue({ response: { status, data: { message: 'private-token' } } }); render(<CompanyBlueprintsView />);
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Blueprint-Katalog' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Blueprint erstellen' })).not.toBeInTheDocument(); expect(screen.queryByText('private-token')).not.toBeInTheDocument();
});
test('uses explicit labels for select controls and offers only the three safe configuration types', async () => {
  await create(); const selector = screen.getByRole('combobox', { name: 'Neue Konfigurationsart' });
  expect(screen.getByLabelText('Neue Konfigurationsart', { exact: true })).toBe(selector);
  expect(screen.getByText('Neue Konfigurationsart', { exact: true })).toHaveAttribute('for', selector.id);
  expect(within(selector).getAllByRole('option').map(option => (option as HTMLOptionElement).value)).toEqual(['screen_lock', 'filevault', 'software_update']);
  expect(screen.getByLabelText('Blueprint-Plattform', { exact: true })).toBe(screen.getByRole('combobox', { name: 'Blueprint-Plattform' }));
  expect(screen.getByText(/WLAN, VPN, Zertifikate und freie Konfigurationen sind nicht verfügbar/)).toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: /JSON|Passwort|Secret/i })).not.toBeInTheDocument();
});
test('creates typed profiles with stable IDs, explicit reason and confirmation, without any allocation effects', async () => {
  await create(); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' }));
  fireEvent.change(screen.getByLabelText('Sperre nach Minuten 1'), { target: { value: '10' } });
  fireEvent.change(screen.getByLabelText('Neue Konfigurationsart'), { target: { value: 'filevault' } }); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'FileVault gewünscht 2' }));
  fireEvent.change(screen.getByLabelText('Neue Konfigurationsart'), { target: { value: 'software_update' } }); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' }));
  fireEvent.change(screen.getByLabelText('Update-Aufschub in Tagen 3'), { target: { value: '30' } });
  prepareWrite('created'); fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' }));
  expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(mock.post).not.toHaveBeenCalled();
  approve(); await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' });
  const body = postBody(); expect(body.draft.configurations).toHaveLength(3);
  expect(body.draft.configurations.map((config: { id: string }) => config.id)).toEqual([id(100), id(101), id(102)]);
  expect(body.draft.configurations.map((config: { payloadJson: string }) => JSON.parse(config.payloadJson))).toEqual([
    { minutes: 10, requirePassword: true }, { enabled: false }, { automatic: true, deferralDays: 30 },
  ]); expect(mock.post.mock.calls[0][0]).toBe(base); expect(mock.post).toHaveBeenCalledTimes(1); expect(mock.put).not.toHaveBeenCalled();
  expect(mock.post.mock.calls[0][2].headers).toEqual({ 'Idempotency-Key': id(104) });
});
test('validation prevents creating invalid numeric payloads or short reasons', async () => {
  await create(); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' }));
  fireEvent.change(screen.getByLabelText('Sperre nach Minuten 1'), { target: { value: '0' } });
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); expect(await screen.findByRole('alert')).toHaveTextContent('gültige Felder'); expect(mock.post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Sperre nach Minuten 1'), { target: { value: '5' } });
  fireEvent.change(screen.getByLabelText('Begründung für die Änderung'), { target: { value: 'short' } });
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
});
test('removes exactly one stable configuration without changing another configuration ID', async () => {
  await create(); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' })); fireEvent.click(screen.getByRole('button', { name: 'Konfiguration hinzufügen' }));
  fireEvent.click(screen.getByRole('button', { name: 'Konfiguration 1 entfernen' }));
  prepareWrite('created'); fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); approve(); await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' });
  expect(postBody().draft.configurations.map((config: { id: string }) => config.id)).toEqual([id(101)]);
});
test('caps typed configurations at 25 without silently dropping rows', async () => {
  await create(); const add = screen.getByRole('button', { name: 'Konfiguration hinzufügen' });
  for (let index = 0; index < 25; index++) fireEvent.click(add);
  expect(add).toBeDisabled(); expect(screen.getByText('Konfigurationen · 25 / 25')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Konfiguration 1 entfernen' })); expect(add).toBeEnabled();
});
test('independently reads actual company apps and records only desired references', async () => {
  await create(); fireEvent.click(screen.getByRole('button', { name: 'App-Auswahl laden' }));
  const choice = await screen.findByRole('checkbox', { name: 'Büro-App · Hersteller' }); fireEvent.click(choice);
  expect(appAccess).toHaveBeenCalledTimes(1); expect(appList).toHaveBeenCalledWith(1, '');
  prepareWrite('created'); fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); approve(); await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' });
  expect(postBody().draft.appPoolIds).toEqual([id(20)]); expect(mock.post).toHaveBeenCalledTimes(1);
});
test('unavailable app source preserves unknown existing references without bypassing backend app authorization', async () => {
  await edit(); appAccess.mockRejectedValue({ response: { status: 403 } }); fireEvent.click(screen.getByRole('button', { name: 'App-Auswahl laden' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Bestehende Referenzen bleiben unverändert');
  expect(screen.getByRole('button', { name: 'App-Pool entfernen ' + id(20) })).toBeInTheDocument(); expect(appList).not.toHaveBeenCalled();
  reason(); mock.put.mockRejectedValue({ response: { status: 403 } }); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve();
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument());
  expect(putBody().draft.appPoolIds).toEqual([id(20)]); expect(screen.queryByRole('region', { name: 'Bestätigter Änderungsnachweis' })).not.toBeInTheDocument();
});
test.each(['actorUserId', 'tenantId'])('changed independent app %s clears draft and all authority-dependent state', async field => {
  await edit(); appAccess.mockResolvedValue({ ...(await appAccess.getMockImplementation()()), [field]: id(99) });
  fireEvent.click(screen.getByRole('button', { name: 'App-Auswahl laden' })); await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Blueprint-Katalog' })).not.toBeInTheDocument(); expect(appList).not.toHaveBeenCalled();
});
test('explicitly removes an unavailable app reference instead of silently rewriting existing drafts', async () => {
  await edit(); appAccess.mockRejectedValue({ response: { status: 403 } }); fireEvent.click(screen.getByRole('button', { name: 'App-Auswahl laden' })); await screen.findByRole('alert');
  fireEvent.click(screen.getByRole('button', { name: 'App-Pool entfernen ' + id(20) })); reason(); prepareWrite('updated');
  fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve(); await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' });
  expect(putBody().draft.appPoolIds).toEqual([]);
});
test('edits with the captured ETag and current capability, without re-reading or substituting a newer head before the write', async () => {
  await edit(); fireEvent.change(screen.getByLabelText('Blueprint-Name'), { target: { value: 'Geänderter Arbeitsplatz' } }); reason(); prepareWrite('updated');
  fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); const before = mock.get.mock.calls.length; approve();
  await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' });
  expect(mock.put.mock.calls[0][2].headers['If-Match']).toBe('"company-blueprint-' + id(1) + '-3"');
  expect(putBody().draft.configurations[0].id).toBe(id(10));
  expect(mock.get.mock.calls.slice(before).map(([url]) => url)).toEqual([base + '/capabilities', base + '/capabilities']);
  expect(screen.queryByRole('region', { name: 'Blueprint-Details' })).not.toBeInTheDocument(); expect(screen.getByText(/kein Nachweis des aktuellen Stands/)).toBeInTheDocument();
});
test('local publication is explicit and reports only a versioned artifact with pending event delivery', async () => {
  await open(); reason(); prepareWrite('published'); fireEvent.click(screen.getByRole('button', { name: 'Version lokal freigeben' })); approve();
  const result = await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' }); expect(result).toHaveTextContent('Version in diesem Nachweis: 2');
  expect(result).toHaveTextContent('Ereigniszustellung: ausstehend'); expect(mock.post.mock.calls[0][0]).toBe(base + '/' + id(1) + '/publish');
  expect(mock.post.mock.calls[0][1]).toEqual({ reason: 'Bewusste neue lokale Konfiguration', confirm: true });
});
test('empty drafts are editable but cannot be published, while app-only drafts may be published', async () => {
  detailData.draft.configurations = []; detailData.draft.appPoolIds = []; detailData.preview = { configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] };
  const rendered = await open(); expect(within(rendered).getByRole('button', { name: 'Version lokal freigeben' })).toBeDisabled(); expect(rendered).toHaveTextContent('mindestens eine Konfiguration oder eine gewünschte Firmen-App');
  fireEvent.click(screen.getByRole('button', { name: 'Details schliessen' })); await screen.findByRole('region', { name: 'Blueprint-Katalog' });
  detailData.draft.appPoolIds = [id(20)]; fireEvent.click(screen.getByRole('button', { name: 'Arbeitsplatz' })); await screen.findByRole('region', { name: 'Blueprint-Details' });
  expect(screen.getByRole('button', { name: 'Version lokal freigeben' })).toBeEnabled();
});
test('shows real conflict provenance and disables publication without selecting an invented winner', async () => {
  detailData.draft.configurations.push({ ...detailData.draft.configurations[0], id: id(11), payloadJson: '{"minutes":10,"requirePassword":true}' });
  detailData.preview = { configurationCount: 2, hasConflicts: true, effectiveConfigurations: [], conflicts: [{ configType: 'screen_lock', variants: [
    { payloadJson: draft().configurations[0].payloadJson, sources: [{ blueprintId: id(1), configurationId: id(10) }] },
    { payloadJson: detailData.draft.configurations[1].payloadJson, sources: [{ blueprintId: id(1), configurationId: id(11) }] },
  ] }] };
  await open(); expect(screen.getByRole('button', { name: 'Version lokal freigeben' })).toBeDisabled();
  const preview = screen.getByRole('region', { name: 'Konfliktprüfung des Entwurfs' }); expect(preview).toHaveTextContent('2 widersprüchliche Profile'); expect(preview).toHaveTextContent(id(10)); expect(preview).toHaveTextContent(id(11));
  expect(mock.post).not.toHaveBeenCalled();
});
test('shows immutable version content and snapshot app metadata, not current app stock', async () => {
  await open(); fireEvent.click(screen.getByRole('button', { name: 'Version 1 ansehen' })); const stored = await screen.findByRole('region', { name: 'Gespeicherte Version 1' });
  expect(stored).toHaveTextContent('Historischer Arbeitsplatz'); expect(stored).toHaveTextContent('Historische Büro-App'); expect(stored).toHaveTextContent('Pool-Revision 99');
  expect(stored).toHaveTextContent('nicht aus aktuellem Lizenzbestand'); expect(stored.querySelector('pre').textContent).toBe(draft().configurations[0].payloadJson); expect(appAccess).not.toHaveBeenCalled();
});
test('restores an explicit immutable version to a draft with current ETag and leaves publication unchanged in receipt', async () => {
  await open(); fireEvent.click(screen.getByRole('button', { name: 'Version 1 ansehen' })); await screen.findByRole('region', { name: 'Gespeicherte Version 1' });
  reason(); prepareWrite('restored'); fireEvent.click(screen.getByRole('button', { name: 'Als Entwurf wiederherstellen' }));
  expect(screen.getByRole('alertdialog')).toHaveTextContent('Version 1 wird nur in den Entwurf übernommen'); approve();
  const result = await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' }); expect(result).toHaveTextContent('Version in diesem Nachweis: 1');
  expect(mock.post.mock.calls[0][0]).toBe(base + '/' + id(1) + '/restore'); expect(mock.post.mock.calls[0][1]).toEqual({ version: 1, reason: 'Bewusste neue lokale Konfiguration', confirm: true });
  expect(mock.post.mock.calls[0][2].headers['If-Match']).toBe(companyBlueprintEtag(detail()));
});
test('displays actual audit proof and reason without pretending pending delivery succeeded', async () => {
  await open(); const history = screen.getByRole('region', { name: 'Blueprint-Historie' }); expect(history).toHaveTextContent('Geprüfte lokale Freigabe');
  expect(history).toHaveTextContent('Revision 1 → 2'); expect(history).toHaveTextContent(id(90)); expect(history).toHaveTextContent(id(93)); expect(history).toHaveTextContent('Zustellung: ausstehend');
});
test('requires explicit recovery of a lost acknowledgement using the identical original body, key and ETag', async () => {
  await edit(); reason(); mock.put.mockRejectedValueOnce({ response: { status: 503 } }); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve();
  const uncertain = await screen.findByRole('region', { name: 'Unbestätigter Änderungsversuch' }); expect(uncertain).toHaveTextContent('könnte bereits gespeichert sein'); expect(mock.put).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederaufnehmen' })).toBeEnabled());
  expect(screen.getByLabelText('Blueprint-Name')).toBeDisabled(); detailData.revision = '77'; prepareWrite('updated', 'already_applied');
  fireEvent.click(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederaufnehmen' })); expect(mock.put).toHaveBeenCalledTimes(1); approve();
  const receipt = await screen.findByRole('region', { name: 'Bestätigter Änderungsnachweis' }); expect(receipt).toHaveTextContent('Revision 4'); expect(receipt).toHaveTextContent('kein Nachweis des aktuellen Stands');
  expect(mock.put.mock.calls[1][1]).toBe(mock.put.mock.calls[0][1]); expect(mock.put.mock.calls[1][2].headers).toEqual(mock.put.mock.calls[0][2].headers);
  fireEvent.click(screen.getByRole('button', { name: 'Aktuellen Blueprint-Stand neu laden' })); await screen.findByRole('region', { name: 'Blueprint-Katalog' }); expect(screen.getByText('77', { exact: true })).toBeInTheDocument();
});
test.each([409, 412])('status %s requires explicit reload and never silently repeats with a fresh version', async status => {
  await edit(); reason(); mock.put.mockRejectedValue({ response: { status } }); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve();
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(status === 412 ? 'inzwischen geändert' : 'Konflikt'));
  expect(mock.put).toHaveBeenCalledTimes(1); expect(screen.queryByRole('region', { name: 'Unbestätigter Änderungsversuch' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Entwurf speichern' })).toBeDisabled(); expect(screen.getByRole('button', { name: 'Aktuellen Stand laden' })).toBeEnabled();
});
test.each([401, 403, 428])('fresh source failure %s clears drafts and blocks the POST', async status => {
  await edit(); reason(); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' }));
  mock.get.mockRejectedValue({ response: { status } }); approve(); await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Blueprint-Katalog' })).not.toBeInTheDocument(); expect(mock.put).not.toHaveBeenCalled();
});
test.each(['actorUserId', 'tenantId'])('preflight %s changes discard confirmation, draft and any write intent', async field => {
  await edit(); reason(); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); accessData[field] = id(99); approve();
  await screen.findByRole('alert'); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument(); expect(mock.put).not.toHaveBeenCalled();
});
test('session events erase captured lost-ACK intents and ignore subsequent late responses', async () => {
  await edit(); reason(); mock.put.mockRejectedValue({ response: { status: 503 } }); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve();
  await screen.findByRole('region', { name: 'Unbestätigter Änderungsversuch' }); act(() => { window.dispatchEvent(new Event('od:session-error')); });
  expect(screen.queryByRole('region', { name: 'Unbestätigter Änderungsversuch' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Blueprint-Katalog' })).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
});
test('closing the editor aborts pending reads and late source completion cannot reopen it', async () => {
  await edit(); const pending = deferred<ReturnType<typeof ok>>(); const original = mock.get.getMockImplementation();
  mock.get.mockImplementation((url, options) => url === base + '/capabilities' ? pending.promise : original(url, options));
  reason(); fireEvent.click(screen.getByRole('button', { name: 'Entwurf speichern' })); approve();
  fireEvent.click(screen.getByRole('button', { name: 'Editor schliessen' }));
  expect(screen.queryByRole('region', { name: 'Blueprint-Editor' })).not.toBeInTheDocument();
  await act(async () => { pending.resolve(ok(accessData)); await pending.promise; });
  await screen.findByRole('region', { name: 'Blueprint-Katalog' }); expect(screen.queryByRole('region', { name: 'Bestätigter Änderungsnachweis' })).not.toBeInTheDocument(); expect(mock.put).not.toHaveBeenCalled();
});
test('unmount discards pending write results and does not call extra refreshes', async () => {
  const rendered = await mount(); fireEvent.click(screen.getByRole('button', { name: 'Blueprint erstellen' }));
  fireEvent.change(screen.getByLabelText('Blueprint-Name'), { target: { value: 'Neuer Arbeitsplatz' } }); reason();
  const pending = deferred<unknown>(); mock.post.mockReturnValue(pending.promise as ReturnType<typeof api.post>);
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); approve(); await waitFor(() => expect(mock.post).toHaveBeenCalledTimes(1));
  const call = mock.post.mock.calls[0]; const reads = mock.get.mock.calls.length; rendered.unmount();
  await act(async () => { pending.resolve({ status: 201, data: envelope({ operationId: call[2].headers['Idempotency-Key'], blueprintId: postBody().id,
    revision: '1', publishedVersion: null, action: 'created', outcome: 'applied', deliveryStatus: 'pending' }) }); await pending.promise; });
  expect(mock.get).toHaveBeenCalledTimes(reads);
});
test('server-side catalogue pagination and bounded search use the requested page rather than client-only slicing', async () => {
  listRows = Array.from({ length: 26 }, (_, index) => ({ id: id(index + 1), name: 'Arbeitsplatz ' + (index + 1) }));
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Nächste Blueprint-Seiten' })); await screen.findByRole('button', { name: 'Arbeitsplatz 26' });
  expect(mock.get).toHaveBeenCalledWith(base, expect.objectContaining({ params: { page: 2, limit: 25 } }));
  fireEvent.change(screen.getByLabelText('Blueprint suchen'), { target: { value: '  Sicher  ' } }); fireEvent.click(screen.getByRole('button', { name: 'Suchen' }));
  await screen.findByRole('button', { name: 'Arbeitsplatz 1' }); expect(mock.get).toHaveBeenCalledWith(base, expect.objectContaining({ params: { page: 1, limit: 25, search: 'Sicher' } }));
});
test('cancelled confirmations perform no writes and preserve the editable draft', async () => {
  await create(); fireEvent.click(screen.getByRole('button', { name: 'Blueprint anlegen' })); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' }));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByLabelText('Blueprint-Name')).toHaveValue('Neuer Arbeitsplatz'); expect(mock.post).not.toHaveBeenCalled();
});
test('HTML-looking labels and historical data remain inert text', async () => {
  listRows[0].name = '<img src=x onerror=alert(1)>'; await mount();
  expect(screen.getByRole('button', { name: '<img src=x onerror=alert(1)>' })).toBeInTheDocument(); expect(document.querySelector('img')).toBeNull();
});
