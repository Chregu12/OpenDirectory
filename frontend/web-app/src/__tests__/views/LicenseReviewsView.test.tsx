import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicenseReviewsView from '../../components/views/LicenseReviewsView';
import { LicenseReview, LicenseReviewPolicy, licenseReviews } from '../../lib/licenseReviews';
import { api } from '../../lib/api';

const licenseId = '11111111-1111-4111-8111-111111111111'; const grantId = '22222222-2222-4222-8222-222222222222';
const policyId = '33333333-3333-4333-8333-333333333333'; const reviewId = '44444444-4444-4444-8444-444444444444';
const userId = '55555555-5555-4555-8555-555555555555'; const recipientId = '66666666-6666-4666-8666-666666666666';
const row = (extra = {}): LicenseReview => ({ id: reviewId, policyId, licenseId, grantId, kind: 'group', recipientId, version: '1', policyVersion: '1', sourceVersion: '2', cycle: '1',
  dueAt: '2026-10-18T10:00:00.000Z', deadlineAt: '2026-10-18T11:00:00.000Z', baseExpiresAt: null, state: 'pending', policyRetired: false, canDecide: true, requiresFreshMfa: false, selfReview: false, ...extra });
const policy = (extra = {}): LicenseReviewPolicy => ({ id: policyId, licenseId, version: '1', intervalSeconds: 86400, windowSeconds: 3600, reviewerUserIds: [userId], createdAt: '2026-10-18T10:00:00.000Z', retiredAt: null, ...extra });
const response = (value: LicenseReview) => ({ status: 200, headers: { etag: `"od-license-review:${value.id}:${value.version}:${value.policyVersion}:${value.sourceVersion}"` }, data: value });
const retained = () => row({ version: '2', cycle: '2', state: 'scheduled', canDecide: false, dueAt: '2026-10-19T10:00:00.000Z', deadlineAt: '2026-10-19T11:00:00.000Z' });
const permissions = ['licenses.reviews.assigned.read', 'licenses.reviews.decide'];
beforeEach(() => {
  jest.clearAllMocks();
  (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/self') ? { status: 200, data: { userId, reviews: [row()], truncated: false } }
    : url.includes('/policies/') ? { status: 200, data: { licenseId, policy: null } } : response(row()));
  (api.post as jest.Mock).mockResolvedValue(response(retained()));
});
async function choose() {
  await userEvent.click(screen.getByRole('button', { name: 'Meine Lizenzprüfungen laden' }));
  await userEvent.click(await screen.findByRole('button', { name: `Ganze Gruppe · ${recipientId} · pending` }));
}
async function acknowledge() {
  await userEvent.type(screen.getByLabelText('Begründung der Lizenzentscheidung'), 'Independent actual recipient certification');
  await userEvent.click(screen.getByLabelText('Quelle, Versionen, Frist und unabhängige Wirkung geprüft.'));
}
test('a named voter confirms only the captured lease, policy and source versions', async () => {
  render(<LicenseReviewsView {...{ permissions, userId }} />); await choose(); await userEvent.click(screen.getByRole('button', { name: 'Lizenzquelle behalten prüfen' }));
  expect(screen.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })).toBeDisabled(); await acknowledge();
  await userEvent.click(screen.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })); await screen.findByText('Bestehende Quelle bestätigt; ursprüngliche Laufzeit unverändert.');
  expect(api.post).toHaveBeenCalledWith('/api/licenses/reviews/' + reviewId + '/decisions', { decision: 'retain', reason: 'Independent actual recipient certification', acknowledgeScope: true }, { headers: { 'If-Match': `"od-license-review:${reviewId}:1:1:2"` } });
});
test('withdrawal explicitly disables the whole group, keeps overlaps and never claims vendor removal', async () => {
  (api.post as jest.Mock).mockResolvedValue(response(row({ version: '2', sourceVersion: '3', state: 'denied', canDecide: false })));
  render(<LicenseReviewsView {...{ permissions, userId }} />); await choose(); await userEvent.click(screen.getByRole('button', { name: 'Lizenzquelle entziehen prüfen' }));
  expect(screen.getByText(/Eine ganze Gruppenregel wird deaktiviert/)).toBeInTheDocument(); await acknowledge();
  await userEvent.click(screen.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })); await screen.findByText('Quelle lokal entzogen. Herstellerstatus separat prüfen.');
});
test.each([412, 428, 503])('a failed write %s cannot be blindly retried or shown as a successful certification', async status => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status } }); render(<LicenseReviewsView {...{ permissions, userId }} />);
  await choose(); await userEvent.click(screen.getByRole('button', { name: 'Lizenzquelle behalten prüfen' })); await acknowledge();
  await userEvent.click(screen.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })); await screen.findByRole('alert');
  expect(api.post).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })).not.toBeInTheDocument();
});
test('a reader sees only a known review and no queue, policy editor or decision controls', async () => {
  (api.get as jest.Mock).mockResolvedValue(response(row({ canDecide: false })));
  render(<LicenseReviewsView permissions={['licenses.reviews.all.read']} userId={userId} />);
  await userEvent.type(screen.getByLabelText('Bekannte Lizenzprüfungs-ID'), reviewId); await userEvent.click(screen.getByRole('button', { name: 'Lizenzprüfung laden' }));
  await screen.findByText(`Ganze Gruppe · ${recipientId} · pending`);
  expect(screen.queryByRole('button', { name: 'Meine Lizenzprüfungen laden' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Lizenzquelle behalten prüfen' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Bekannte Lizenzpool-ID')).not.toBeInTheDocument();
});
test('configuration needs an explicit cutoff acknowledgement and only posts named reviewer IDs', async () => {
  (api.post as jest.Mock).mockResolvedValue({ status: 201, headers: { etag: `"od-license-review-policy:${policyId}:1"` }, data: policy() });
  render(<LicenseReviewsView permissions={['licenses.reviews.policies.read', 'licenses.reviews.policies.manage']} userId={userId} />);
  await userEvent.type(screen.getByLabelText('Bekannte Lizenzpool-ID'), licenseId); await userEvent.click(screen.getByRole('button', { name: 'Lizenzprüfrichtlinie laden' })); await screen.findByText('Keine Richtlinie für diesen Pool');
  await userEvent.type(screen.getByLabelText('Unabhängige Prüfer-IDs (kommagetrennt)'), userId); await userEvent.type(screen.getByLabelText('Begründung der Richtlinie'), 'Independent recurring source review policy');
  expect(screen.getByRole('button', { name: 'Lizenzprüfrichtlinie verbindlich erstellen' })).toBeDisabled();
  await userEvent.click(screen.getByLabelText('Fristen und Entzug geprüft; Stilllegen hebt bestehende Fristen nicht auf.')); await userEvent.click(screen.getByRole('button', { name: 'Lizenzprüfrichtlinie verbindlich erstellen' }));
  await screen.findByText('Richtlinie bestätigt. Bestehende Fristen bleiben verbindlich.');
  expect(api.post).toHaveBeenCalledWith('/api/licenses/reviews/policies', { licenseId, intervalSeconds: 86400, windowSeconds: 3600, reviewerUserIds: [userId], reason: 'Independent recurring source review policy', acknowledgeDeadlines: true });
});
test('a late queue cannot populate a different canonical human context', async () => {
  let finish: (value: unknown) => void = () => {};
  (api.get as jest.Mock).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const rendered = render(<LicenseReviewsView {...{ permissions, userId }} />); await userEvent.click(screen.getByRole('button', { name: 'Meine Lizenzprüfungen laden' }));
  rendered.rerender(<LicenseReviewsView permissions={permissions} userId={recipientId} />);
  await act(async () => finish({ status: 200, data: { userId, reviews: [row()], truncated: false } }));
  expect(screen.queryByRole('button', { name: `Ganze Gruppe · ${recipientId} · pending` })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Meine Lizenzprüfungen laden' })).toBeEnabled();
});
test('combined administrative duties cannot reuse a policy acknowledgement as a source-decision confirmation', async () => {
  render(<LicenseReviewsView permissions={[...permissions, 'licenses.reviews.policies.read', 'licenses.reviews.policies.manage']} userId={userId} />);
  await userEvent.type(screen.getByLabelText('Bekannte Lizenzpool-ID'), licenseId); await userEvent.click(screen.getByRole('button', { name: 'Lizenzprüfrichtlinie laden' })); await screen.findByText('Keine Richtlinie für diesen Pool');
  await userEvent.type(screen.getByLabelText('Begründung der Richtlinie'), 'A different policy configuration acknowledgement');
  await userEvent.click(screen.getByLabelText('Fristen und Entzug geprüft; Stilllegen hebt bestehende Fristen nicht auf.'));
  await choose(); await userEvent.click(screen.getByRole('button', { name: 'Lizenzquelle behalten prüfen' }));
  expect(screen.queryByLabelText('Begründung der Richtlinie')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Quelle, Versionen, Frist und unabhängige Wirkung geprüft.')).not.toBeChecked();
  expect(screen.getByLabelText('Begründung der Lizenzentscheidung')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })).toBeDisabled(); expect(api.post).not.toHaveBeenCalled();
});
test('loss of voter authority discards an already opened decision form', async () => {
  const rendered = render(<LicenseReviewsView {...{ permissions, userId }} />); await choose(); await userEvent.click(screen.getByRole('button', { name: 'Lizenzquelle behalten prüfen' })); await acknowledge();
  rendered.rerender(<LicenseReviewsView permissions={['licenses.reviews.all.read']} userId={userId} />);
  expect(screen.queryByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test.each([
  { ...response(row()), status: 202 }, { ...response(row()), headers: { etag: 'wrong' } }, response(row({ licenseId: 'wrong' })), response(row({ version: '0' })),
  response(row({ canDecide: true, selfReview: true })), response(row({ state: 'expired', canDecide: true })), response(row({ deadlineAt: null })),
])('strict review reads reject ambiguous, wrong-scope and internally contradictory evidence', async invalid => {
  (api.get as jest.Mock).mockResolvedValue(invalid); await expect(licenseReviews.get(reviewId)).rejects.toThrow();
});
test.each([
  response(retained()), response(row({ version: '2', cycle: '2', sourceVersion: '3', state: 'scheduled', canDecide: false })),
  response(row({ version: '2', state: 'pending', canDecide: false })), response(row({ version: '2', cycle: '2', state: 'exempt', canDecide: false })),
])('a retain receipt cannot retarget the captured scope or change its retirement meaning', async invalid => {
  const malformed = invalid.data.state === 'scheduled' && invalid.data.sourceVersion === '2' ? { ...invalid, data: { ...invalid.data, extra: true } } : invalid;
  (api.post as jest.Mock).mockResolvedValue(malformed); await expect(licenseReviews.decide(row(), 'retain', 'Reviewed exact source')).rejects.toThrow();
});
test('queue authority is bound to its canonical human rather than a display name or cached session', async () => {
  await expect(licenseReviews.self(recipientId)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
