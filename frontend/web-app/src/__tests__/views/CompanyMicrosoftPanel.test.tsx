import React from 'react';
import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import CompanyMicrosoftPanel from '@/components/views/CompanyMicrosoftPanel';
import { CompanyPool } from '@/lib/companyApplications';
import { api } from '@/lib/api';
import { microsoftId as id, microsoftContext, microsoftEnvelope, microsoftState, microsoftMappings, microsoftProducts, microsoftPool, microsoftHistory, microsoftPreview, microsoftSyncReceipt, microsoftResponse as ok } from '../fixtures/companyMicrosoft';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const pool: CompanyPool = { id: id(8), tenantId: id(2), revision: '1', name: 'Büro-Lizenz', vendor: 'Microsoft', description: '', totalSeats: 2, usedSeats: 1, availableSeats: 1, licenseType: 'per_user', allocationMode: 'local-only', createdAt: '2026-11-16T00:00:00.000Z', updatedAt: '2026-11-16T00:00:00.000Z' };
beforeEach(() => {
  jest.resetAllMocks(); let sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/state')) return ok(microsoftState());
    if (url.endsWith('/mappings')) return ok(microsoftMappings());
    if (url.endsWith('/products')) return ok(microsoftProducts());
    if (url.endsWith('/history')) return ok(microsoftHistory());
    throw new Error('Unexpected Microsoft read');
  });
});
function open() { fireEvent.click(screen.getByText('Microsoft 365 · Verknüpfungen dieses Lizenzpools')); }
async function load() { open(); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Verknüpfungen laden' })); await screen.findByRole('region', { name: 'Microsoft-Produktverknüpfung' }); }
test('pool mapping requires explicit product selection, a reason and confirmation before exactly one write', async () => {
  render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled(); await load();
  fireEvent.change(screen.getByLabelText('Begründung der Microsoft-Verknüpfung'), { target: { value: 'Produktzuordnung ausdrücklich geprüft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Produkte laden' })); await screen.findByLabelText('Microsoft-Produkt auswählen');
  fireEvent.change(screen.getByLabelText('Microsoft-Produkt auswählen'), { target: { value: id(9) } }); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Produkt verknüpfen' }));
  const dialog = screen.getByRole('alertdialog'); expect(within(dialog).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(api.post).not.toHaveBeenCalled();
  (api.post as jest.Mock).mockImplementation(async (_url, _body, config) => { const operation = config.headers['Idempotency-Key']; return ok({ ...microsoftEnvelope, pool: { ...microsoftPool(), id: operation }, historical: false }, 201, { etag: `"company-microsoft-pool-${operation}-1"` }); });
  fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diese Microsoft-Verknüpfung.' })); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  await screen.findByText(/Vorgang gespeichert/); expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: 'Microsoft-Produkt verknüpfen' })).toBeDisabled();
  expect(pool.usedSeats).toBe(1); expect(screen.getByText(/Eine Verknüpfung allein weist noch keine Cloud-Lizenz zu/)).toBeInTheDocument();
});
test('missing operator configuration is visible and has no hidden cloud mutation', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/state') ? ok({ ...microsoftEnvelope, state: 'not_configured', microsoftTenantId: null, connection: null }) : url.endsWith('/mappings') ? ok({ ...microsoftMappings(), users: [] }) : ok(microsoftHistory()));
  render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); open(); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Verknüpfungen laden' }));
  await screen.findByText(/noch keine freigegebene Microsoft-Verbindung/); expect(screen.queryByRole('button', { name: 'Microsoft-Verbindung bestätigen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('source rejection clears the connection and notifies the owning company view', async () => {
  const denied = jest.fn(), failure = { response: { status: 428 } }; (api.get as jest.Mock).mockRejectedValue(failure);
  render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={denied} />); open(); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Verknüpfungen laden' }));
  await waitFor(() => expect(denied).toHaveBeenCalledWith(failure)); expect(screen.queryByRole('region', { name: 'Microsoft-Produktverknüpfung' })).not.toBeInTheDocument();
});
test('provider failure does not revoke independent local company access or expose its error body', async () => {
  const denied = jest.fn(); render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={denied} />); await load();
  (api.get as jest.Mock).mockRejectedValueOnce({ response: { status: 503 }, message: 'private-provider-secret' }); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Produkte laden' }));
  await screen.findByRole('alert'); expect(denied).not.toHaveBeenCalled(); expect(screen.queryByText('private-provider-secret')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['not_configured', 'configuration_unavailable', 'review_required'])('existing mappings can be retired when configuration is %s without querying Microsoft', async status => {
  const current = { ...microsoftState(), state: status, ...(['not_configured', 'configuration_unavailable'].includes(status) ? { microsoftTenantId: null, readClientId: undefined, writeClientId: undefined } : { microsoftTenantId: id(99) }) };
  (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/state') ? ok(current) : url.endsWith('/mappings') ? ok({ ...microsoftMappings(), pool: microsoftPool() }) : ok(microsoftHistory()));
  render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); await load();
  fireEvent.change(screen.getByLabelText('Begründung der Microsoft-Verknüpfung'), { target: { value: 'Alte Produktverknüpfung zurückgeben' } });
  fireEvent.click(screen.getByRole('button', { name: 'Produktverknüpfung entfernen' })); const dialog = screen.getByRole('alertdialog'); expect(within(dialog).getByText(new RegExp('Firmenpool ' + id(8)))).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Microsoft-Verbindung neu prüfen' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/products'))).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test.each(['session', 'company'])('a late connection read cannot restore a previous %s view', async change => {
  let resolve!: (value: unknown) => void; (api.get as jest.Mock).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  const view = render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); open(); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Verknüpfungen laden' }));
  const signal = (api.get as jest.Mock).mock.calls[0][1].signal;
  if (change === 'session') act(() => window.dispatchEvent(new Event('od:session-error')));
  else view.rerender(<CompanyMicrosoftPanel context={{ ...microsoftContext, tenantId: id(99) }} pool={{ ...pool, tenantId: id(99) }} onAccessError={jest.fn()} />);
  expect(signal.aborted).toBe(true); await act(async () => resolve(ok(microsoftState())));
  expect(screen.queryByRole('region', { name: 'Microsoft-Produktverknüpfung' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('a real local entitlement is presented as a proposed cloud action without dispatch or ownership', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/state') ? ok(microsoftState()) : url.endsWith('/mappings') ? ok({ ...microsoftMappings(), pool: microsoftPool() }) : ok(microsoftHistory()));
  (api.post as jest.Mock).mockResolvedValue(ok(microsoftPreview())); render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); await load();
  fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Lizenzabgleich prüfen' })); const preview = await screen.findByRole('region', { name: 'Microsoft-Lizenzabgleich-Vorschau' });
  expect(within(preview).getByRole('heading', { name: 'Microsoft-Lizenz zuweisen' })).toBeInTheDocument(); expect(within(preview).getByText(/Lokaler Anspruch: vorhanden/)).toBeInTheDocument();
  expect(within(preview).getByText(/Noch keine Cloud-Änderung ausgelöst/)).toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
  expect((api.post as jest.Mock).mock.calls[0][0]).toMatch(/\/preview$/);
});
test('cloud sync requires its own reason and explicit confirmation and reports acknowledgement as pending', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/state') ? ok(microsoftState()) : url.endsWith('/mappings') ? ok({ ...microsoftMappings(), pool: microsoftPool() }) : ok(microsoftHistory()));
  (api.post as jest.Mock).mockImplementation(async (url: string, _body: unknown, config: any) => url.endsWith('/preview') ? ok(microsoftPreview()) : ok(microsoftSyncReceipt(config.headers['Idempotency-Key'])));
  render(<CompanyMicrosoftPanel context={microsoftContext} pool={pool} onAccessError={jest.fn()} />); await load(); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Lizenzabgleich prüfen' })); await screen.findByRole('region', { name: 'Microsoft-Lizenzabgleich-Vorschau' });
  fireEvent.change(screen.getByLabelText('Begründung des Microsoft-Lizenzabgleichs'), { target: { value: 'Lizenzabgleich ausdrücklich geprüft' } }); fireEvent.click(screen.getByRole('button', { name: 'Microsoft-Lizenzabgleich vorbereiten' }));
  const dialog = screen.getByRole('alertdialog', { name: 'Microsoft-Lizenzabgleich bestätigen' }); expect(within(dialog).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(api.post).toHaveBeenCalledTimes(1);
  fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diesen Microsoft-Lizenzabgleich.' })); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  const result = await screen.findByRole('region', { name: 'Microsoft-Lizenzabgleich-Ergebnis' }); expect(within(result).getByRole('heading', { name: 'Anbieterbestätigung ausstehend' })).toBeInTheDocument(); expect(within(result).getByText(/tatsächliche Wirkung muss/)).toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('button', { name: 'Microsoft-Lizenzabgleich prüfen' })).toBeDisabled();
});
