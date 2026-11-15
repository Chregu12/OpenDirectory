import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import CompanyLicenseProviderPanel from '@/components/views/CompanyLicenseProviderPanel';
import { api } from '@/lib/api';
import { CompanyApplicationsCapabilities } from '@/lib/companyApplications';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn() } }));
const actorUserId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const cloudId = '33333333-3333-4333-8333-333333333333';
const context: CompanyApplicationsCapabilities = { schemaVersion: 1, companyLicenseProtocol: 1, actorUserId, tenantId,
  permissions: ['company.apps.read'], allocationMode: 'local-only', supportedTargets: ['user'] };
const envelope = { schemaVersion: 1, companyLicenseProviderProtocol: 1, actorUserId, tenantId, provider: 'microsoft-365' };
const product = { skuId: cloudId, skuPartNumber: 'ACTUAL_PRODUCT', appliesTo: 'User', capabilityStatus: 'Enabled',
  prepaidUnits: { enabled: 12, warning: 2, suspended: 1, lockedOut: 0 }, consumedUnits: 7 };
const connected = { ...envelope, state: 'connected', microsoftTenantId: cloudId, checkedAt: '2026-11-15T18:00:00.000Z', products: [product] };
function open() { fireEvent.click(screen.getByText('Microsoft 365 · Anbieterbestand')); }
function inspect() { fireEvent.click(screen.getByRole('button', { name: 'Verbindung prüfen' })); }
beforeEach(() => { jest.resetAllMocks(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: connected }); });

test('provider access is explicitly requested and displays actual counts separately from local allocations', async () => {
  render(<CompanyLicenseProviderPanel context={context} />); expect(api.get).not.toHaveBeenCalled(); open(); inspect();
  expect(await screen.findByText('ACTUAL_PRODUCT')).toBeInTheDocument(); expect(screen.getByText('12')).toBeInTheDocument(); expect(screen.getByText('7')).toBeInTheDocument();
  expect(screen.getByText('Warnung').parentElement).toHaveTextContent('Warnung2'); expect(screen.getByText('Ausgesetzt').parentElement).toHaveTextContent('Ausgesetzt1');
  expect(screen.getByText('Gesperrt').parentElement).toHaveTextContent('Gesperrt0'); expect(screen.getByText(/lokalen Firmen-Zuweisungen bleiben separat/)).toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith('/api/licenses/company/provider', { signal: expect.any(AbortSignal) });
});
test.each([
  [{ ...envelope, state: 'not_configured' }, /noch keine Microsoft-365-Verbindung/],
  [{ ...connected, products: [] }, /keine Lizenzprodukte zurückgegeben/],
  [{ ...envelope, state: 'failed', errorCode: 'graph_capacity_http_403' }, /Leseberechtigung und Administratorzustimmung/],
  [{ ...envelope, state: 'failed', errorCode: 'graph_capacity_http_429', retryAfter: 90 }, /Wartezeit: 90 Sekunden/],
])('an actual empty, absent or denied result has an explicit state', async (data, text) => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data }); render(<CompanyLicenseProviderPanel context={context} />); open(); inspect();
  expect(await screen.findByText(text)).toBeInTheDocument(); expect(screen.queryByText('ACTUAL_PRODUCT')).not.toBeInTheDocument();
});
test.each([
  { ...connected, tenantId: cloudId }, { ...connected, actorUserId: cloudId }, { ...connected, debug: 'private.fixture.secret' },
  { ...connected, products: [product, product] }, { ...connected, products: [{ ...product, consumedUnits: -1 }] },
])('unbound or malformed observations cannot become a confirmed connection', async data => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data }); render(<CompanyLicenseProviderPanel context={context} />); open(); inspect();
  expect(await screen.findByRole('alert')).toHaveTextContent(/konnte nicht bestätigt/); expect(screen.queryByText('ACTUAL_PRODUCT')).not.toBeInTheDocument();
});
test('failed refresh removes the previous provider products without invalidating independent local pools', async () => {
  const denied = jest.fn(); render(<CompanyLicenseProviderPanel context={context} onAccessError={denied} />); open(); inspect();
  await screen.findByText('ACTUAL_PRODUCT'); (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 }, message: 'private.fixture.secret' }); inspect();
  expect(screen.queryByText('ACTUAL_PRODUCT')).not.toBeInTheDocument(); expect(await screen.findByRole('alert')).toHaveTextContent(/konnte nicht bestätigt/);
  expect(denied).not.toHaveBeenCalled(); expect(screen.queryByText('private.fixture.secret')).not.toBeInTheDocument();
});
test.each([401, 403, 428])('source denial %s notifies the owning license view to clear its access', async status => {
  const denied = jest.fn(); const failure = { response: { status } }; (api.get as jest.Mock).mockRejectedValue(failure);
  render(<CompanyLicenseProviderPanel context={context} onAccessError={denied} />); open(); inspect();
  await waitFor(() => expect(denied).toHaveBeenCalledWith(failure)); expect(screen.queryByText('ACTUAL_PRODUCT')).not.toBeInTheDocument();
});
test.each(['session', 'company'])('a late observation cannot restore results after a %s change', async change => {
  let resolve!: (value: unknown) => void; (api.get as jest.Mock).mockImplementation(() => new Promise(done => { resolve = done; }));
  const view = render(<CompanyLicenseProviderPanel context={context} />); open(); inspect(); const signal = (api.get as jest.Mock).mock.calls[0][1].signal;
  if (change === 'session') act(() => { window.dispatchEvent(new Event('od:session-error')); });
  else view.rerender(<CompanyLicenseProviderPanel context={{ ...context, tenantId: cloudId }} />);
  expect(signal.aborted).toBe(true); await act(async () => { resolve({ status: 200, data: connected }); });
  expect(screen.queryByText('ACTUAL_PRODUCT')).not.toBeInTheDocument(); expect(screen.queryByText(/Microsoft-Verbindung bestätigt/)).not.toBeInTheDocument();
});
