import React from 'react';
import { act,render,screen,waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PrivilegedAccessPolicyView from '../../components/views/PrivilegedAccessPolicyView';
import { privilegedAccessPolicy } from '../../lib/privilegedAccessPolicy';
import { api } from '../../lib/api';

jest.mock('../../lib/auth',()=>({ startLogin:jest.fn() }));
const access = { subject:'pim-policy-operator',userId:'11111111-1111-4111-8111-111111111111',demoMode:false,permissions:['pim.policies.read','pim.policies.manage'] };
const row = (extra = {}) => ({ role:'license-manager',version:'1',required:false,maxDurationSeconds:28800,reviewerUserIds:[],protected:false,locked:false,canManage:true,requiresFreshMfa:false,...extra });
const input = { required:true,maxDurationSeconds:600,reviewerUserIds:[],reason:'Reviewed mandatory least privilege policy',acknowledgeInvalidation:true as const };
beforeEach(()=>{ jest.clearAllMocks(); (api.get as jest.Mock).mockResolvedValue({ status:200,data:row() }); (api.put as jest.Mock).mockResolvedValue({ status:200,data:row({ version:'2',required:true,maxDurationSeconds:600 }) }); });
async function load() {
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für PIM-Richtlinie'),'license-manager');
  await userEvent.click(screen.getByRole('button',{ name:'PIM-Richtlinie laden' })); await screen.findByText('license-manager · Version 1');
}
async function review() {
  await userEvent.click(screen.getByLabelText('PIM-Aktivierung verbindlich verlangen'));
  const duration = screen.getByLabelText('Maximale PIM-Aktivierungsdauer in Sekunden'); await userEvent.clear(duration); await userEvent.type(duration,'600');
  await userEvent.type(screen.getByLabelText('Begründung der PIM-Richtlinie'),input.reason);
  await userEvent.click(screen.getByRole('button',{ name:'PIM-Richtlinie prüfen' }));
}
test('known-role status has no profiles and writes only after explicit destructive-effect acknowledgement',async()=>{
  render(<PrivilegedAccessPolicyView access={access} />); await load(); await review();
  const save = screen.getByRole('button',{ name:'PIM-Richtlinie verbindlich speichern' }); expect(save).toBeDisabled(); expect(api.put).not.toHaveBeenCalled();
  await userEvent.click(screen.getByLabelText('Rechteentzug und Wiederherstellung geprüft')); await userEvent.click(save);
  await screen.findByText(/PIM-Richtlinie für license-manager bestätigt/);
  expect(api.put).toHaveBeenCalledWith('/api/identity/pim/policies/license-manager',input,{ headers:{ 'If-Match':'"od-role-activation:license-manager:1"' } });
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.get).toHaveBeenCalledWith('/api/identity/pim/policies/license-manager',{ signal:expect.any(AbortSignal) });
});
test.each([{ canManage:false,requiresFreshMfa:false },{ canManage:false,requiresFreshMfa:true },{ protected:true,canManage:false }])('read-only and insufficient-proof policy cannot become editable: %j',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:row(extra) }); render(<PrivilegedAccessPolicyView access={access} />); await load();
  expect(screen.queryByRole('button',{ name:'PIM-Richtlinie prüfen' })).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test('losing authority closes a stale reviewed form even if the next response still advertises editing',async()=>{
  const view = render(<PrivilegedAccessPolicyView access={access} />); await load(); await review();
  view.rerender(<PrivilegedAccessPolicyView access={{ ...access,permissions:['pim.policies.read'] }} />);
  await waitFor(()=>expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()); expect(api.put).not.toHaveBeenCalled();
});
test('a late receipt cannot announce success for a different current actor',async()=>{
  let finish!: (response: any) => void; (api.put as jest.Mock).mockImplementation(()=>new Promise(resolve=>{ finish=resolve; }));
  const view = render(<PrivilegedAccessPolicyView access={access} />); await load(); await review();
  await userEvent.click(screen.getByLabelText('Rechteentzug und Wiederherstellung geprüft')); await userEvent.click(screen.getByRole('button',{ name:'PIM-Richtlinie verbindlich speichern' }));
  view.rerender(<PrivilegedAccessPolicyView access={{ ...access,subject:'independent-reader',permissions:['pim.policies.read'] }} />);
  await act(async()=>finish({ status:200,data:row({ version:'2',required:true,maxDurationSeconds:600 }) }));
  expect(screen.queryByText(/PIM-Richtlinie für license-manager bestätigt/)).not.toBeInTheDocument();
});
test('conflicts and lost results show no success and cannot be blindly replayed',async()=>{
  (api.put as jest.Mock).mockRejectedValue({ response:{ status:412,data:{ error:'activation_policy_changed' } } });
  render(<PrivilegedAccessPolicyView access={access} />); await load(); await review();
  await userEvent.click(screen.getByLabelText('Rechteentzug und Wiederherstellung geprüft')); await userEvent.click(screen.getByRole('button',{ name:'PIM-Richtlinie verbindlich speichern' }));
  await screen.findByText(/wurde inzwischen geändert/); expect(api.put).toHaveBeenCalledTimes(1); expect(screen.getByRole('button',{ name:'PIM-Richtlinie verbindlich speichern' })).toBeDisabled();
});
test.each([{ required:'true' },{ maxDurationSeconds:59 },{ maxDurationSeconds:28801 },{ role:'other-role' },{ version:'0' },{ locked:true },{ ignored:true },{ reviewerUserIds:null },{ reviewerUserIds:['not-canonical'] },{ reviewerUserIds:['11111111-1111-4111-8111-111111111111','11111111-1111-4111-8111-111111111111'] }])('malformed source cannot grant editability: %j',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:row(extra) }); render(<PrivilegedAccessPolicyView access={access} />);
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für PIM-Richtlinie'),'license-manager'); await userEvent.click(screen.getByRole('button',{ name:'PIM-Richtlinie laden' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('button',{ name:'PIM-Richtlinie prüfen' })).not.toBeInTheDocument();
});
test.each([{ status:207,data:row({ version:'2',required:true,maxDurationSeconds:600 }) },{ status:200,data:row({ required:true,maxDurationSeconds:600 }) },{ status:200,data:row({ version:'2',required:false,maxDurationSeconds:600 }) },{ status:200,data:row({ version:'2',required:true,maxDurationSeconds:1200 }) }])('partial or mismatched receipts are not successful writes: %j',async response=>{
  (api.put as jest.Mock).mockResolvedValue(response); await expect(privilegedAccessPolicy.change(row(),input)).rejects.toThrow(); expect(api.put).toHaveBeenCalledTimes(1);
});
