import React from 'react';
import { render,screen,within,waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AppAssignmentsView from '../../components/views/AppAssignmentsView';
import { api } from '../../lib/api';
import { applicationAssignments } from '../../lib/applicationAssignments';

const own = '11111111-1111-4111-8111-111111111111'; const target = '22222222-2222-4222-8222-222222222222'; const id = '33333333-3333-4333-8333-333333333333';
const access = { permissions: ['applications.assignments.read','applications.assignments.manage'],subject: 'verified',userId: own,clientId: 'console',demoMode: false };
const row = (extra = {}) => ({ id,clientId: 'registered-app',targetType: 'user' as const,targetId: target,targetRevision: '1',reason: 'Reviewed application access',durationSeconds: 3600,
  createdAt: '2026-10-18T10:00:00.000Z',expiresAt: '2026-10-18T11:00:00.000Z',revokedAt: null,status: 'active' as const,...extra });
let rows: any[]; let canManage: boolean;
beforeEach(() => {
  jest.clearAllMocks(); rows = []; canManage = true;
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (!url.endsWith('/assignments')) throw new Error('Unexpected directory or metadata access');
    return { data: { clientId: url.split('/')[3],name: 'Actual application',assignmentRequired: true,protected: !canManage,canManage,assignments: rows,truncated: false } };
  });
  (api.post as jest.Mock).mockImplementation(async (_url: string,input: any) => {
    const created = row({ id: input.requestId,targetType: input.targetType,targetId: input.targetId,reason: input.reason,durationSeconds: input.durationSeconds,
      expiresAt: new Date(Date.parse(row().createdAt)+input.durationSeconds*1000).toISOString() });
    rows = [created]; return { status: 201,data: { assignment: created,reused: false } };
  });
  (api.delete as jest.Mock).mockImplementation(async () => { rows = [row({ status: 'revoked',revokedAt: '2026-10-18T10:30:00.000Z' })]; return { status: 200,data: { assignment: rows[0] } }; });
});
async function prepare(type = 'user',identifier = target) {
  render(<AppAssignmentsView access={access} selectedClientId="registered-app" />); const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText('Zieltyp'),type); await user.type(screen.getByLabelText('Kanonische Ziel-ID'),identifier);
  await user.type(screen.getByLabelText('Begründung der Anwendungszuweisung'),'Reviewed independent application access');
  await user.click(screen.getByRole('button',{ name: 'Anwendungszuweisung prüfen' })); return user;
}
test('an ordinary actor does not list assignments or receive guessed metadata', () => {
  render(<AppAssignmentsView access={{ ...access,permissions: [] }} selectedClientId="registered-app" />); expect(api.get).not.toHaveBeenCalled(); expect(screen.queryByLabelText('Kanonische Ziel-ID')).not.toBeInTheDocument();
});
test('an access reader loads a known client without profile/registration authority or write controls', async () => {
  rows = [row()]; render(<AppAssignmentsView access={{ ...access,permissions: ['applications.assignments.read'] }} selectedClientId="registered-app" />);
  await screen.findByText('Zugriff für Actual application'); expect(screen.queryByRole('button',{ name: 'Anwendungszuweisung prüfen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button',{ name: 'Zuweisung widerrufen' })).not.toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith('/api/clients/registered-app/assignments',expect.any(Object)); expect(api.get).toHaveBeenCalledTimes(1);
});
test.each(['user','group'])('a %s assignment requires confirmation and canonical namespace, bounded duration, reason and request UUID only', async type => {
  const user = await prepare(type); expect(api.post).not.toHaveBeenCalled(); await user.click(screen.getByRole('button',{ name: 'Zuweisungsänderung bestätigen' }));
  await screen.findByText(/Zuweisung für registered-app bestätigt/); const [url,input] = (api.post as jest.Mock).mock.calls[0];
  expect(url).toBe('/api/clients/registered-app/assignments'); expect(Object.keys(input).sort()).toEqual(['durationSeconds','reason','requestId','targetId','targetType']);
  expect(input).toMatchObject({ targetType: type,targetId: target,durationSeconds: 86400,reason: 'Reviewed independent application access' }); expect(input.requestId).toMatch(/^[a-f0-9-]{36}$/);
});
test('cancellation never dispatches a grant', async () => {
  const user = await prepare(); await user.click(screen.getByRole('button',{ name: 'Schließen und Stand prüfen' })); expect(api.post).not.toHaveBeenCalled();
});
test('canonical self assignment is refused in the form before a network mutation', async () => {
  await prepare('user',own); await screen.findByRole('alert'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('self revocation and protected-client mutation controls are absent rather than inferred from admin-like names', async () => {
  rows = [row({ targetId: own })]; const rendered = render(<AppAssignmentsView access={access} selectedClientId="registered-app" />); await screen.findByText('Zugriff für Actual application');
  expect(screen.queryByRole('button',{ name: 'Zuweisung widerrufen' })).not.toBeInTheDocument();
  canManage = false; rows = []; rendered.rerender(<AppAssignmentsView access={access} selectedClientId="protected-app" />); await screen.findByText('Privilegierte Anwendung: Änderungen nur durch globale Administration.'); expect(screen.queryByLabelText('Kanonische Ziel-ID')).not.toBeInTheDocument();
});
test('source outage clears the read and never presents a sample or successful empty assignment list', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 } }); render(<AppAssignmentsView access={access} selectedClientId="registered-app" />); await screen.findByRole('alert'); expect(screen.queryByText('Keine Zuweisungen.')).not.toBeInTheDocument();
});
test('uncertain writes stay unconfirmed and cannot automatically replay the immutable grant', async () => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status: 503 } }); const user = await prepare(); await user.click(screen.getByRole('button',{ name: 'Zuweisungsänderung bestätigen' }));
  await within(screen.getByRole('dialog')).findByRole('alert'); expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('button',{ name: 'Zuweisungsänderung bestätigen' })).toBeDisabled(); expect(screen.queryByText(/Zuweisung für registered-app bestätigt/)).not.toBeInTheDocument();
});
test.each([202,207])('HTTP %s cannot acknowledge a grant merely because an assignment-shaped field exists', async status => {
  (api.post as jest.Mock).mockResolvedValue({ status,data: { assignment: row(),reused: false } }); const user = await prepare(); await user.click(screen.getByRole('button',{ name: 'Zuweisungsänderung bestätigen' })); await within(screen.getByRole('dialog')).findByRole('alert');
});
test('revocation is explicitly confirmed and does not resend actor or secret fields', async () => {
  rows = [row()]; render(<AppAssignmentsView access={access} selectedClientId="registered-app" />); const user = userEvent.setup(); await user.click(await screen.findByRole('button',{ name: 'Zuweisung widerrufen' })); expect(api.delete).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button',{ name: 'Zuweisungsänderung bestätigen' })); await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/clients/registered-app/assignments/'+id));
});
test('a selected-client change closes a stale confirmation instead of applying it to a newly displayed target', async () => {
  const rendered = render(<AppAssignmentsView access={access} selectedClientId="registered-app" />); const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Kanonische Ziel-ID'),target); await user.type(screen.getByLabelText('Begründung der Anwendungszuweisung'),'Reviewed independent application access');
  await user.click(screen.getByRole('button',{ name: 'Anwendungszuweisung prüfen' })); expect(screen.getByRole('dialog')).toBeInTheDocument();
  rendered.rerender(<AppAssignmentsView access={access} selectedClientId="other-app" />);
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument()); expect(api.post).not.toHaveBeenCalled();
});
test('a mismatched revocation receipt cannot rewrite immutable expiry or report success', async () => {
  (api.delete as jest.Mock).mockResolvedValue({ status: 200,data: { assignment: row({ status: 'revoked',revokedAt: '2026-10-18T10:30:00.000Z',reason: 'Unexpected replacement reason' }) } });
  await expect(applicationAssignments.revoke('registered-app',row())).rejects.toThrow('nicht bestätigt');
});
