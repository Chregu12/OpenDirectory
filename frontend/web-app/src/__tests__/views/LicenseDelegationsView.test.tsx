import React from 'react';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicenseDelegationsView from '../../components/views/LicenseDelegationsView';
import { api } from '../../lib/api';
const licenseId='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const delegationId='33333333-3333-4333-8333-333333333333';const target='44444444-4444-4444-8444-444444444444';
const lease=(duty='allocator')=>({id:delegationId,licenseId,userId,duty,version:'1',createdAt:'2026-10-18T10:00:00.000Z',expiresAt:'2026-10-18T11:00:00.000Z',revokedAt:null,state:'active'});
const permissions=['licenses.delegations.self'];
beforeEach(()=>{jest.clearAllMocks();(api.get as jest.Mock).mockImplementation(async(url:string)=>({status:200,data:url.endsWith('/self')?{userId,delegations:[lease()],truncated:false}:{id:licenseId,name:'Scoped pool',vendor:null,licenseType:'per_user',totalSeats:3,usedSeats:0}}));
  (api.post as jest.Mock).mockResolvedValue({status:201,data:{licenseId,assigneeType:'user',assigneeId:target,localOnly:true,status:'assigned'}});});
async function choose(){await userEvent.click(screen.getByRole('button',{name:'Meine Pool-Delegationen laden'}));await userEvent.click(await screen.findByRole('button',{name:new RegExp(licenseId+' · allocator')}));await screen.findByText('Delegierter Pool: Scoped pool');}
async function open(){await choose();await userEvent.type(screen.getByLabelText('Kanonisches Lizenzziel'),target);await userEvent.click(screen.getByRole('button',{name:'Pool-Zuweisung prüfen'}));}
async function acknowledge(){await userEvent.type(screen.getByLabelText('Begründung der Pool-Aktion'),'Independent exact resource confirmation');await userEvent.click(screen.getByLabelText('Pool, Ziel, Aufgabe und Wirkung unabhängig geprüft.'));}
test('a delegate has no global catalog or delegation controls and explicitly confirms a scoped local-only allocation',async()=>{
  render(<LicenseDelegationsView {...{permissions,userId}}/>);expect(screen.queryByLabelText('Bekannte Pool-ID für Delegation')).not.toBeInTheDocument();await open();
  expect(screen.getByRole('button',{name:'Pool-Aktion verbindlich bestätigen'})).toBeDisabled();await acknowledge();await userEvent.click(screen.getByRole('button',{name:'Pool-Aktion verbindlich bestätigen'}));
  await screen.findByText('Quelle lokal vergeben; Herstellerstatus separat prüfen.');expect(api.post).toHaveBeenCalledTimes(1);expect((api.post as jest.Mock).mock.calls[0][0]).toBe('/api/licenses/scoped/pools/'+licenseId+'/assign');
});
test.each([403,412,428,503])('an uncertain mutation %s is not a success or a blind-retry control',async status=>{
  (api.post as jest.Mock).mockRejectedValue({response:{status}});render(<LicenseDelegationsView {...{permissions,userId}}/>);await open();await acknowledge();await userEvent.click(screen.getByRole('button',{name:'Pool-Aktion verbindlich bestätigen'}));
  await screen.findByRole('alert');expect(api.post).toHaveBeenCalledTimes(1);expect(screen.queryByRole('button',{name:'Pool-Aktion verbindlich bestätigen'})).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Pool-Zuweisung prüfen'})).toBeDisabled();
});
test('a changed canonical identity discards late own leases and any prepared acknowledgement',async()=>{
  let finish:(value:unknown)=>void=()=>{};(api.get as jest.Mock).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));const rendered=render(<LicenseDelegationsView {...{permissions,userId}}/>);
  await userEvent.click(screen.getByRole('button',{name:'Meine Pool-Delegationen laden'}));rendered.rerender(<LicenseDelegationsView permissions={permissions} userId={target}/>);
  await act(async()=>finish({status:200,data:{userId,delegations:[lease()],truncated:false}}));expect(screen.queryByRole('button',{name:new RegExp(licenseId)})).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Meine Pool-Delegationen laden'})).toBeEnabled();
});
test('permission loss closes an acknowledged mutation before it can be posted',async()=>{
  const rendered=render(<LicenseDelegationsView {...{permissions,userId}}/>);await open();await acknowledge();rendered.rerender(<LicenseDelegationsView permissions={[]} userId={userId}/>);
  expect(screen.queryByRole('button',{name:'Pool-Aktion verbindlich bestätigen'})).not.toBeInTheDocument();expect(api.post).not.toHaveBeenCalled();
});
test('a known-pool reader gets no control-plane writer or allocation controls',async()=>{
  (api.get as jest.Mock).mockResolvedValue({status:200,data:{licenseId,delegations:[lease()],hasMore:false,nextAfter:null}});render(<LicenseDelegationsView permissions={['licenses.delegations.read']} userId={userId}/>);
  await userEvent.type(screen.getByLabelText('Bekannte Pool-ID für Delegation'),licenseId);await userEvent.click(screen.getByRole('button',{name:'Pool-Delegationen laden'}));await screen.findByText(/Version 1/);
  expect(screen.queryByRole('button',{name:'Delegation widerrufen'})).not.toBeInTheDocument();expect(screen.queryByLabelText('Kanonische Delegate-ID')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Meine Pool-Delegationen laden'})).not.toBeInTheDocument();
});
