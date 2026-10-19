import React from 'react';
import { render,screen,waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RoleAuthenticationView from '../../components/views/RoleAuthenticationView';
import { roleAuthentication } from '../../lib/roleAuthentication';
import { api } from '../../lib/api';

jest.mock('../../lib/auth',()=>({ startLogin:jest.fn() }));
const access = { subject:'security-operator',userId:'11111111-1111-4111-8111-111111111111',demoMode:false,permissions:['authentication.policies.read','authentication.policies.manage'] };
const row = (extra = {}) => ({ role:'license-manager',version:'1',required:false,maxAgeSeconds:3600,protected:false,locked:false,canManage:true,requiresFreshMfa:false,...extra });
beforeEach(()=>{ jest.clearAllMocks(); (api.get as jest.Mock).mockResolvedValue({ status:200,data:row() }); (api.put as jest.Mock).mockResolvedValue({ status:200,data:row({ version:'2',required:true,maxAgeSeconds:300 }) }); });
async function load() {
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für MFA-Richtlinie'),'license-manager'); await userEvent.click(screen.getByRole('button',{ name:'Rollenrichtlinie laden' }));
  await screen.findByText('license-manager · Version 1');
}
async function confirm() {
  await userEvent.click(screen.getByLabelText('MFA für diese Rolle verlangen'));
  const age = screen.getByLabelText('Maximales Rollen-Anmeldealter in Sekunden'); await userEvent.clear(age); await userEvent.type(age,'300');
  await userEvent.type(screen.getByLabelText('Begründung der Rollenrichtlinie'),'Reviewed cross-client MFA requirement');
  await userEvent.click(screen.getByRole('button',{ name:'Rollenrichtlinie prüfen' }));
}
test('minimal known-role read and confirmed conditional write never fetch profiles or role assignments', async()=>{
  render(<RoleAuthenticationView access={access} />); await load(); await confirm(); expect(api.put).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole('button',{ name:'Rollenrichtlinie verbindlich speichern' })); await screen.findByText(/Rollenrichtlinie bestätigt für license-manager/);
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.get).toHaveBeenCalledWith('/api/identity/authentication/roles/license-manager',{ signal:expect.any(AbortSignal) });
  expect(api.put).toHaveBeenCalledWith('/api/identity/authentication/roles/license-manager',{ required:true,maxAgeSeconds:300,reason:'Reviewed cross-client MFA requirement' },{ headers:{ 'If-Match':'"od-role-authentication:license-manager:1"' } });
});
test.each([{ canManage:false,requiresFreshMfa:false },{ canManage:false,requiresFreshMfa:true },{ canManage:false,requiresFreshMfa:false,locked:true,required:true,maxAgeSeconds:300 }])('reader, fresh-login and fixed-policy views cannot submit writes: %j',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:row(extra) }); render(<RoleAuthenticationView access={access} />); await load();
  expect(screen.queryByRole('button',{ name:'Rollenrichtlinie prüfen' })).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test('losing policy management closes old confirmation even when a stale response still advertises editability',async()=>{
  const view = render(<RoleAuthenticationView access={access} />); await load(); await confirm();
  view.rerender(<RoleAuthenticationView access={{ ...access,permissions:['authentication.policies.read'] }} />);
  await waitFor(()=>expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()); expect(screen.queryByRole('button',{ name:'Rollenrichtlinie prüfen' })).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test('conflict has no success or automatic retry and requires an explicit reload',async()=>{
  (api.put as jest.Mock).mockRejectedValue({ response:{ status:412,data:{ error:'authentication_policy_changed' } } });
  render(<RoleAuthenticationView access={access} />); await load(); await confirm(); await userEvent.click(screen.getByRole('button',{ name:'Rollenrichtlinie verbindlich speichern' }));
  await screen.findByText(/wurde inzwischen geändert/); expect(api.put).toHaveBeenCalledTimes(1); expect(screen.getByRole('button',{ name:'Rollenrichtlinie verbindlich speichern' })).toBeDisabled();
});
test.each([{ required:'true' },{ maxAgeSeconds:299 },{ role:'other-role' },{ version:'0' },{ ignored:true }])('malformed or mismatched source %j cannot become editable policy',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:row(extra) }); render(<RoleAuthenticationView access={access} />);
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für MFA-Richtlinie'),'license-manager'); await userEvent.click(screen.getByRole('button',{ name:'Rollenrichtlinie laden' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('button',{ name:'Rollenrichtlinie prüfen' })).not.toBeInTheDocument();
});
test.each([{ status:207,data:row({ version:'2',required:true,maxAgeSeconds:300 }) },{ status:200,data:row({ required:true,maxAgeSeconds:300 }) },{ status:200,data:row({ version:'2',required:false,maxAgeSeconds:300 }) }])('partial or mismatched receipt cannot be a successful role change: %j',async response=>{
  (api.put as jest.Mock).mockResolvedValue(response); await expect(roleAuthentication.change(row(),{ required:true,maxAgeSeconds:300,reason:'Reviewed actual policy change' })).rejects.toThrow(); expect(api.put).toHaveBeenCalledTimes(1);
});
