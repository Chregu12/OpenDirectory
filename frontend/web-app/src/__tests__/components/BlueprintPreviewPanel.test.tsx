import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import BlueprintPreviewPanel from '@/components/views/BlueprintPreviewPanel';
import BlueprintConfigurationView from '@/components/views/BlueprintConfigurationView';
import { BlueprintRecord, blueprintConfiguration } from '@/lib/blueprintConfiguration';
import { PolicyAccess, policyGovernance } from '@/lib/policyGovernance';
import { BlueprintPreviewResult, blueprintPreview } from '@/lib/blueprintPreview';

jest.mock('@/lib/policyGovernance', () => ({ policyGovernance: { access: jest.fn() } }));
jest.mock('@/lib/blueprintConfiguration', () => ({ blueprintConfiguration: { list: jest.fn(), get: jest.fn(), write: jest.fn() } }));
jest.mock('@/lib/blueprintPreview', () => ({ ...jest.requireActual('@/lib/blueprintPreview'), blueprintPreview: { compare: jest.fn() } }));
jest.mock('@/components/views/PolicyCommandPanel', () => () => null);
const authority = policyGovernance as jest.Mocked<typeof policyGovernance>;
const preview = blueprintPreview as jest.Mocked<typeof blueprintPreview>;
const catalogue = blueprintConfiguration as jest.Mocked<typeof blueprintConfiguration>;
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const identity: PolicyAccess = { schemaVersion: 4, subject: 'original-operator', userId: id(10), permissions: ['policies.read', 'policies.preview'], freshMfa: false, writeAuthenticationMaxAgeSeconds: 300 };
const rows: BlueprintRecord[] = [{ id: id(1), name: 'Blueprint Alpha', platform: 'all', version: 3, created_by: id(10) }, { id: id(2), name: 'Blueprint Beta', platform: 'macos', version: 4, created_by: id(10) }];
const source = (blueprint: number, configuration: number) => ({ blueprintId: id(blueprint), configurationId: id(configuration) });
const fixture = (): BlueprintPreviewResult => ({
  schemaVersion: 1, scope: 'selected-blueprint-versions', comparison: 'whole-config-type', platform: 'macos', previewOnly: true, enforcementConfirmed: false, licenseReservations: 0,
  blueprints: [{ id: id(1), name: 'Blueprint Alpha', platform: 'all', version: 3 }], configurationCount: 3, hasConflicts: true,
  effectiveConfigurations: [{ configType: 'wifi', payloadJson: '{"ssid": "Büro"}', sources: [source(1, 101)] }],
  conflicts: [{ configType: 'screen_lock', variants: [{ payloadJson: '{"number": 9007199254740992}', sources: [source(1, 102)] }, { payloadJson: '{"number": 9007199254740993}', sources: [source(1, 103)] }] }],
});
function deferred<Value>() {
  let resolve: (value: Value) => void; let reject: (failure: unknown) => void;
  const promise = new Promise<Value>((accepted, failed) => { resolve = accepted; reject = failed; });
  return { promise, resolve: (value: Value) => resolve(value), reject: (failure: unknown) => reject(failure) };
}
const opener = () => screen.getByRole('button', { name: 'Ausgewählte Blueprint-Versionen vergleichen' });
const select = (name = 'Blueprint Alpha') => fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(name) }));
const calculate = () => fireEvent.click(screen.getByRole('button', { name: 'Vorschau berechnen' }));
const open = () => { fireEvent.click(opener()); select(); };
const result = () => screen.findByRole('region', { name: 'Bestätigte Auswahlvorschau' });
beforeEach(() => { jest.resetAllMocks(); authority.access.mockResolvedValue(identity); preview.compare.mockResolvedValue(fixture()); catalogue.list.mockResolvedValue(rows); });

test('starts collapsed without checkboxes, API calls or automatic snapshots, even after selecting', () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />);
  expect(opener()).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  open(); expect(authority.access).not.toHaveBeenCalled(); expect(preview.compare).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Vorschau berechnen' })).toBeEnabled();
});
test('keeps the plain introduction visible and technical limits in a closed details element', () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); fireEvent.click(opener());
  const platform = screen.getByRole('combobox', { name: 'Vorschau-Plattform' });
  expect(screen.getByLabelText('Vorschau-Plattform', { exact: true })).toBe(platform);
  expect(screen.getByText('Vorschau-Plattform', { exact: true })).toHaveAttribute('for', platform.id);
  expect(screen.getByText('Vergleicht nur ausgewählte aktuelle Versionen; keine Änderungen an Geräten oder Lizenzen.')).toBeVisible();
  const details = screen.getByText('Prüfumfang und Grenzen').closest('details'); expect(details).not.toHaveAttribute('open');
  expect(details).toHaveTextContent('Platform-Policy-Scope'); expect(details).toHaveTextContent('keine unveränderliche Versionshistorie');
  expect(details).toHaveTextContent('keine Priorität und kein Gewinner'); expect(details).toHaveTextContent('Keine Apple-Validierung');
});
test.each([[], ['policies.read'], ['policies.preview'], ['company.apps.read', 'company.apps.assign'], ['policies.manage', 'policies.deploy']].map(permissions => [permissions]))('requires both explicit existing policy rights, not company ownership or writes: %j', permissions => {
  render(<BlueprintPreviewPanel rows={rows} access={{ ...identity, permissions }} />);
  expect(screen.queryByRole('button')).not.toBeInTheDocument(); expect(authority.access).not.toHaveBeenCalled(); expect(preview.compare).not.toHaveBeenCalled();
});
test('rechecks the same original actor and both rights without imposing MFA on a read', async () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result();
  expect(authority.access).toHaveBeenCalledWith(expect.any(AbortSignal)); expect(preview.compare).toHaveBeenCalledTimes(1);
  expect(preview.compare).toHaveBeenCalledWith({ platform: 'macos', blueprints: [{ id: id(1), version: 3 }] }, expect.any(AbortSignal));
  expect(catalogue.write).not.toHaveBeenCalled(); expect(catalogue.list).not.toHaveBeenCalled(); expect(catalogue.get).not.toHaveBeenCalled();
});
test.each([
  ['changed user', { userId: id(11) }], ['changed subject', { subject: 'another-subject' }], ['lost read right', { permissions: ['policies.preview'] }],
  ['lost preview right', { permissions: ['policies.read'] }], ['owner-only authority', { permissions: ['company.apps.read'] }],
])('blocks before preview when current authority has %s', async (_label, changes) => {
  authority.access.mockResolvedValue({ ...identity, ...changes }); render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate();
  await screen.findByRole('alert'); expect(preview.compare).not.toHaveBeenCalled(); expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument();
});
test('an unavailable authority cannot produce a preview or silently reuse cached access', async () => {
  authority.access.mockRejectedValue(new Error('private source detail')); render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate();
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(screen.queryByText('private source detail')).not.toBeInTheDocument(); expect(preview.compare).not.toHaveBeenCalled();
});
test('shows selected versions, exact source IDs, raw payload text and unresolved conflicts without a winner', async () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); const comparison = await result();
  expect(comparison).toHaveTextContent('3 Quellkonfigurationen'); expect(comparison).toHaveTextContent('Version 3'); expect(comparison).toHaveTextContent(id(101));
  expect(comparison).toHaveTextContent('Keine automatische Auflösung'); expect(comparison).toHaveTextContent('0 Lizenzreservierungen');
  expect(within(comparison).getByRole('region', { name: 'Nicht widersprüchliche Konfigurationsarten' })).toHaveTextContent('wifi');
  expect(within(comparison).getByRole('region', { name: 'Konflikte der Auswahl' })).toHaveTextContent('2 abweichende vollständige Profile');
  const raw = within(comparison).getByText('{"number": 9007199254740993}'); expect(raw.tagName).toBe('PRE'); expect(raw.textContent).toBe('{"number": 9007199254740993}');
  expect(within(comparison).getByText('{"number": 9007199254740992}')).toBeInTheDocument();
  for (const summary of within(comparison).getAllByText('Unverändertes Konfigurations-JSON anzeigen')) expect(summary.closest('details')).not.toHaveAttribute('open');
});
test('renders HTML-looking opaque JSON as text, never markup', async () => {
  const data = fixture(); data.effectiveConfigurations[0].payloadJson = '{"html":"<img src=x onerror=alert(1)>"}'; preview.compare.mockResolvedValue(data);
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); const comparison = await result();
  expect(within(comparison).getByText(data.effectiveConfigurations[0].payloadJson)).toBeInTheDocument(); expect(comparison.querySelector('img')).toBeNull();
});
test('labels an empty conflict-free comparison as selected-only, not effective device enforcement', async () => {
  preview.compare.mockResolvedValue({ ...fixture(), configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] });
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); const comparison = await result();
  expect(comparison).toHaveTextContent('Keine Konflikte innerhalb dieser Auswahl'); expect(comparison).toHaveTextContent('Keine Aussage über weitere Zuweisungen');
  expect(comparison).toHaveTextContent('keine Bestätigung einer wirksamen Gerätekonfiguration');
});
test('selection changes discard success immediately without fetching replacement versions', async () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result(); select('Blueprint Beta');
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(preview.compare).toHaveBeenCalledTimes(1); expect(catalogue.list).not.toHaveBeenCalled();
});
test.each(['windows', 'linux'])('changing the platform to %s clears selected versions and success without a POST', async platform => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result();
  fireEvent.change(screen.getByLabelText('Vorschau-Plattform'), { target: { value: platform } });
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Vorschau berechnen' })).toBeDisabled(); expect(screen.getByRole('checkbox', { name: /Blueprint Alpha/ })).not.toBeChecked();
  select(); calculate(); await waitFor(() => expect(preview.compare).toHaveBeenCalledTimes(2));
  expect(preview.compare).toHaveBeenLastCalledWith({ platform, blueprints: [{ id: id(1), version: 3 }] }, expect.any(AbortSignal));
});
test('caps explicit selection at 25 without silently truncating or selecting all catalogue rows', async () => {
  const many = Array.from({ length: 26 }, (_, index) => ({ ...rows[0], id: id(index + 1), name: `Blueprint ${index + 1}` }));
  render(<BlueprintPreviewPanel rows={many} access={identity} />); fireEvent.click(opener()); const checkboxes = screen.getAllByRole('checkbox');
  for (const checkbox of checkboxes.slice(0, 25)) fireEvent.click(checkbox);
  expect(checkboxes[25]).toBeDisabled(); expect(screen.getByText(/25 \/ 25 ausdrücklich/)).toBeInTheDocument(); calculate();
  await waitFor(() => expect(preview.compare).toHaveBeenCalledTimes(1)); expect(preview.compare.mock.calls[0][0].blueprints).toHaveLength(25);
  fireEvent.click(checkboxes[0]); expect(checkboxes[25]).toBeEnabled();
});
test('an empty catalogue offers no sample versions and cannot submit', () => {
  render(<BlueprintPreviewPanel rows={[]} access={identity} />); fireEvent.click(opener());
  expect(screen.getByText('Keine Katalogversionen verfügbar. Keine Beispieldaten.')).toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Vorschau berechnen' })).toBeDisabled(); expect(preview.compare).not.toHaveBeenCalled();
});
test('a failed subsequent request removes stale success and never automatically retries or reloads snapshots', async () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result();
  preview.compare.mockRejectedValue({ response: { status: 412 } }); calculate();
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument();
  expect(await screen.findByRole('alert')).toHaveTextContent('Version nicht mehr aktuell'); expect(preview.compare).toHaveBeenCalledTimes(2);
  expect(catalogue.list).not.toHaveBeenCalled(); expect(catalogue.get).not.toHaveBeenCalled();
});
test.each([404, 409, 400, 503])('error %s is not a successful empty comparison', async status => {
  preview.compare.mockRejectedValue({ response: { status } }); render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate();
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(preview.compare).toHaveBeenCalledTimes(1);
});
test('a double click cannot create concurrent previews', async () => {
  const pending = deferred<PolicyAccess>(); authority.access.mockReturnValue(pending.promise);
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); calculate();
  expect(authority.access).toHaveBeenCalledTimes(1); await act(async () => { pending.resolve(identity); await pending.promise; });
  await result(); expect(preview.compare).toHaveBeenCalledTimes(1);
});
test.each(['selection', 'platform', 'collapse', 'session'])('changing %s while authority is pending prevents the POST', async change => {
  const pending = deferred<PolicyAccess>(); authority.access.mockReturnValue(pending.promise);
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); const signal = authority.access.mock.calls[0][0];
  if (change === 'selection') select('Blueprint Beta');
  if (change === 'platform') fireEvent.change(screen.getByLabelText('Vorschau-Plattform'), { target: { value: 'linux' } });
  if (change === 'collapse') fireEvent.click(opener());
  if (change === 'session') act(() => { window.dispatchEvent(new CustomEvent('od:session-error')); });
  expect(signal.aborted).toBe(true); await act(async () => { pending.resolve(identity); await pending.promise; });
  expect(preview.compare).not.toHaveBeenCalled(); expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument();
});
test.each(['selection', 'platform', 'collapse', 'session', 'unmount'])('changing %s during preview aborts and discards a late response', async change => {
  const pending = deferred<BlueprintPreviewResult>(); preview.compare.mockReturnValue(pending.promise);
  const view = render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await waitFor(() => expect(preview.compare).toHaveBeenCalledTimes(1));
  const signal = preview.compare.mock.calls[0][1];
  if (change === 'selection') select('Blueprint Beta');
  if (change === 'platform') fireEvent.change(screen.getByLabelText('Vorschau-Plattform'), { target: { value: 'linux' } });
  if (change === 'collapse') fireEvent.click(opener());
  if (change === 'session') act(() => { window.dispatchEvent(new CustomEvent('od:session-error')); });
  if (change === 'unmount') view.unmount();
  expect(signal.aborted).toBe(true); await act(async () => { pending.resolve(fixture()); await pending.promise; });
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(preview.compare).toHaveBeenCalledTimes(1);
});
test.each(['version', 'name', 'platform', 'removed row', 'user', 'subject', 'permission'])('a changed bound %s invalidates in-flight previews and captured inputs', async change => {
  const pending = deferred<BlueprintPreviewResult>(); preview.compare.mockReturnValue(pending.promise);
  const view = render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await waitFor(() => expect(preview.compare).toHaveBeenCalledTimes(1));
  const nextRows = rows.map(row => ({ ...row })); let access = identity;
  if (change === 'version') nextRows[0].version = 5;
  if (change === 'name') nextRows[0].name = 'Renamed blueprint';
  if (change === 'platform') nextRows[0].platform = 'linux';
  if (change === 'removed row') nextRows.pop();
  if (change === 'user') access = { ...identity, userId: id(11) };
  if (change === 'subject') access = { ...identity, subject: 'new-subject' };
  if (change === 'permission') access = { ...identity, permissions: ['policies.read'] };
  view.rerender(<BlueprintPreviewPanel rows={nextRows} access={access} />); expect(preview.compare.mock.calls[0][1].aborted).toBe(true);
  await act(async () => { pending.resolve(fixture()); await pending.promise; });
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
test('changed rows also discard already completed results without fetching new versions', async () => {
  const view = render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result();
  view.rerender(<BlueprintPreviewPanel rows={[{ ...rows[0], version: 5 }, rows[1]]} access={identity} />);
  expect(opener()).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(preview.compare).toHaveBeenCalledTimes(1);
});
test('an obsolete failed response cannot remove a newer successful explicit comparison', async () => {
  const first = deferred<BlueprintPreviewResult>(); preview.compare.mockReturnValueOnce(first.promise).mockResolvedValueOnce(fixture());
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await waitFor(() => expect(preview.compare).toHaveBeenCalledTimes(1));
  select('Blueprint Beta'); calculate(); await result();
  await act(async () => { first.reject(new Error('obsolete failure')); await first.promise.catch(() => undefined); });
  expect(screen.getByRole('region', { name: 'Bestätigte Auswahlvorschau' })).toBeInTheDocument(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
test('a session error discards completed results, selection and expanded state', async () => {
  render(<BlueprintPreviewPanel rows={rows} access={identity} />); open(); calculate(); await result();
  act(() => { window.dispatchEvent(new CustomEvent('od:session-error')); });
  expect(screen.queryByRole('region', { name: 'Bestätigte Auswahlvorschau' })).not.toBeInTheDocument(); expect(opener()).toHaveAttribute('aria-expanded', 'false'); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
  fireEvent.click(opener()); expect(screen.getByRole('button', { name: 'Vorschau berechnen' })).toBeDisabled(); expect(preview.compare).toHaveBeenCalledTimes(1);
});
test('the parent mounts the collapsed panel for explicit read and preview rights without MFA', async () => {
  render(<BlueprintConfigurationView />); await screen.findByText('Blueprint Alpha');
  expect(opener()).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(preview.compare).not.toHaveBeenCalled();
});
test('the parent grants no new panel or catalogue access to a company owner without policy read rights', async () => {
  authority.access.mockResolvedValue({ ...identity, permissions: [] }); render(<BlueprintConfigurationView />); await screen.findByText('Keine Blueprint-Leseberechtigung.');
  expect(screen.queryByRole('button', { name: 'Ausgewählte Blueprint-Versionen vergleichen' })).not.toBeInTheDocument(); expect(catalogue.list).not.toHaveBeenCalled(); expect(preview.compare).not.toHaveBeenCalled();
});
