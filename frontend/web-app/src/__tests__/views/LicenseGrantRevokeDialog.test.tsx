import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicenseGrantRevokeDialog from '../../components/views/LicenseGrantRevokeDialog';
import { api } from '../../lib/api';
import { LicenseGrant, readLicenseGrant, revokeLicenseGrant } from '../../lib/licenseGrants';

const licenseId = '11111111-1111-4111-8111-111111111111';
const grantId = '22222222-2222-4222-8222-222222222222';
const record = (extra = {}): LicenseGrant => ({ id: grantId, licenseId, kind: 'group', recipientId: '33333333-3333-4333-8333-333333333333',
  version: '3', origin: 'allocated', createdAt: '2026-10-18T10:00:00.000Z', expiresAt: null, state: 'active', sourceUsers: 2, ...extra });
const response = (grant: LicenseGrant) => ({ status: 200, data: grant, headers: { etag: `"od-license-grant:${grant.id}:${grant.version}"` } });
const receipt = () => ({ ...response(record({ version: '4', state: 'revoked', sourceUsers: 0 })), data: {
  grant: record({ version: '4', state: 'revoked', sourceUsers: 0 }), localOnly: true, sourcesRemoved: 2, usersRetainingAssignment: 1,
} });

beforeEach(() => {
  jest.clearAllMocks();
  (api.get as jest.Mock).mockResolvedValue(response(record()));
  (api.post as jest.Mock).mockResolvedValue(receipt());
});

async function confirm() {
  await screen.findByText(/Ganze Gruppenregel/);
  await userEvent.type(screen.getByLabelText('Begründung (10–500 Zeichen)'), 'Individually reviewed source withdrawal');
  await userEvent.click(screen.getByLabelText('Ich bestätige den Entzug dieser Quelle und Version.'));
}

test('the dialog reads the exact source before confirmation and submits only its captured conditional version', async () => {
  const onRevoked = jest.fn();
  render(<LicenseGrantRevokeDialog {...{ licenseId, grantId, onRevoked }} onClose={jest.fn()} />);
  await screen.findByText(/Ganze Gruppenregel/);
  expect(screen.getByRole('button', { name: 'Geprüfte Quelle entziehen' })).toBeDisabled();
  expect(screen.getByText(/Herstellerentzug ist nicht bestätigt/)).toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled(); await confirm();
  await userEvent.click(screen.getByRole('button', { name: 'Geprüfte Quelle entziehen' }));
  await waitFor(() => expect(onRevoked).toHaveBeenCalledWith(1));
  expect(api.post).toHaveBeenCalledWith(`/api/licenses/${licenseId}/grants/${grantId}/revoke`, { confirm: true, reason: 'Individually reviewed source withdrawal' }, { headers: { 'If-Match': `"od-license-grant:${grantId}:3"` } });
});

test.each([412, 428, 503])('a failed conditional write (%s) cannot be blindly repeated or reported as revoked', async status => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status } }); const onRevoked = jest.fn();
  render(<LicenseGrantRevokeDialog {...{ licenseId, grantId, onRevoked }} onClose={jest.fn()} />); await confirm();
  await userEvent.click(screen.getByRole('button', { name: 'Geprüfte Quelle entziehen' })); await screen.findByRole('alert');
  expect(onRevoked).not.toHaveBeenCalled(); expect(screen.getByRole('button', { name: 'Geprüfte Quelle entziehen' })).toBeDisabled();
  expect(api.post).toHaveBeenCalledTimes(1);
});

test('inactive and observed historical sources are not mislabeled as newly approved grants', async () => {
  (api.get as jest.Mock).mockResolvedValue(response(record({ state: 'expired', origin: 'observed' })));
  render(<LicenseGrantRevokeDialog {...{ licenseId, grantId }} onClose={jest.fn()} onRevoked={jest.fn()} />);
  await screen.findByText(/Übernommener Altbestand/); expect(screen.getByRole('button', { name: 'Geprüfte Quelle entziehen' })).toBeDisabled();
});

test('a late source read cannot populate a different grant context', async () => {
  let finish: (value: unknown) => void = () => {};
  (api.get as jest.Mock).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const alternate = '44444444-4444-4444-8444-444444444444';
  (api.get as jest.Mock).mockResolvedValueOnce(response(record({ id: alternate, recipientId: 'new-recipient' })));
  const rendered = render(<LicenseGrantRevokeDialog {...{ licenseId, grantId }} onClose={jest.fn()} onRevoked={jest.fn()} />);
  rendered.rerender(<LicenseGrantRevokeDialog licenseId={licenseId} grantId={alternate} onClose={jest.fn()} onRevoked={jest.fn()} />);
  await screen.findByText(/new-recipient/); await act(async () => finish(response(record())));
  expect(screen.queryByText(/33333333-3333-4333-8333-333333333333/)).not.toBeInTheDocument();
});

test.each([
  { ...response(record()), status: 202 }, { ...response(record()), headers: { etag: 'wrong' } }, response(record({ version: '0' })),
  response(record({ sourceUsers: -1 })), response(record({ id: 'other' })), response(record({ licenseId: 'other' })),
  response({ ...record(), extra: true } as LicenseGrant), response(record({ expiresAt: 'invalid' })),
])('source reads reject invalid envelopes, versions, scopes and metadata', async invalid => {
  (api.get as jest.Mock).mockResolvedValue(invalid);
  await expect(readLicenseGrant(licenseId, grantId)).rejects.toThrow();
});

test.each([
  { ...receipt(), status: 202 }, { ...receipt(), headers: { etag: 'wrong' } },
  { ...receipt(), data: { ...receipt().data, localOnly: false } },
  { ...receipt(), data: { ...receipt().data, sourcesRemoved: 1 } },
  { ...receipt(), data: { ...receipt().data, usersRetainingAssignment: 3 } },
  { ...receipt(), data: { ...receipt().data, grant: record({ state: 'revoked', sourceUsers: 0 }) } },
  { ...receipt(), data: { ...receipt().data, grant: record({ version: '4', state: 'active', sourceUsers: 0 }) } },
])('withdrawal never accepts an ambiguous or scope-mismatched receipt', async invalid => {
  (api.post as jest.Mock).mockResolvedValue(invalid);
  await expect(revokeLicenseGrant(record(), 'Reviewed withdrawal')).rejects.toThrow();
});
