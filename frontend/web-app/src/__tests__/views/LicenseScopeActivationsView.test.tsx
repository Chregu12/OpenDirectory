import React from'react';
import{act,render,screen}from'@testing-library/react';import userEvent from'@testing-library/user-event';
import LicenseScopeActivationsView from'../../components/views/LicenseScopeActivationsView';import{api}from'../../lib/api';
const userId='22222222-2222-4222-8222-222222222222';const licenseId='11111111-1111-4111-8111-111111111111';const eligibilityId='33333333-3333-4333-8333-333333333333';const reviewer='44444444-4444-4444-8444-444444444444';const requestId='55555555-5555-4555-8555-555555555555';
const eligible={id:eligibilityId,licenseId,userId,duty:'allocator',version:'1',maxDurationSeconds:3600,reviewerUserIds:[reviewer],createdAt:'2026-10-18T10:00:00.000Z',expiresAt:'2026-10-18T11:00:00.000Z',revokedAt:null,state:'active'};
const pending={id:requestId,eligibilityId,licenseId,userId,duty:'allocator',version:'1',status:'pending',requestedDurationSeconds:600,requestedAt:'2026-10-18T10:01:00.000Z',approvalDeadline:'2026-10-18T10:16:00.000Z',reviewedAt:null,activatedAt:null,grantId:null,grantExpiresAt:null,canReview:false,canActivate:false,canCancel:true,canDeactivate:false};
const permissions=['licenses.delegations.self'];
beforeEach(()=>{jest.clearAllMocks();(api.get as jest.Mock).mockResolvedValue({status:200,data:{userId,eligibilities:[eligible],requests:[],truncated:false}});(api.post as jest.Mock).mockResolvedValue({status:201,data:pending,headers:{etag:`"od-license-scope-activation:${requestId}:1"`}});});
async function open(){await userEvent.click(screen.getByRole('button',{name:'Meine Pool-PIM-Einträge laden'}));await userEvent.click(await screen.findByRole('button',{name:'Pool-Aktivierung beantragen prüfen'}));}
async function confirm(){await userEvent.type(screen.getByLabelText('Begründung der Pool-PIM-Aktion'),'Independent explicit temporary pool authority');await userEvent.click(screen.getByLabelText('Pool, unabhängige Freigabe, Version und Laufzeit geprüft.'));await userEvent.click(screen.getByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen'}));}
test('a prepared request is not an approval or activation and a successful receipt leaves reload usable',async()=>{
 render(<LicenseScopeActivationsView {...{permissions,userId}}/>);await open();expect(screen.getByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen'})).toBeDisabled();await confirm();
 await screen.findByText('Aktivierung beantragt; noch keine aktiven Rechte.');expect(screen.getByRole('button',{name:'Meine Pool-PIM-Einträge laden'})).toBeEnabled();expect(api.post).toHaveBeenCalledTimes(1);expect(screen.queryByLabelText('PIM-Pool-ID')).not.toBeInTheDocument();
});
test.each([412,428,503])('an uncertain request %s cannot be blindly retried or displayed as active',async status=>{
 (api.post as jest.Mock).mockRejectedValue({response:{status}});render(<LicenseScopeActivationsView {...{permissions,userId}}/>);await open();await confirm();await screen.findByRole('alert');expect(screen.queryByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen'})).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Pool-Aktivierung beantragen prüfen'})).toBeDisabled();expect(api.post).toHaveBeenCalledTimes(1);
});
test('changing canonical human discards a late queue rather than lending eligibility to another session',async()=>{
 let finish:(value:unknown)=>void=()=>{};(api.get as jest.Mock).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));const rendered=render(<LicenseScopeActivationsView {...{permissions,userId}}/>);await userEvent.click(screen.getByRole('button',{name:'Meine Pool-PIM-Einträge laden'}));rendered.rerender(<LicenseScopeActivationsView permissions={permissions} userId={reviewer}/>);
 await act(async()=>finish({status:200,data:{userId,eligibilities:[eligible],requests:[],truncated:false}}));expect(screen.queryByRole('button',{name:'Pool-Aktivierung beantragen prüfen'})).not.toBeInTheDocument();
});
test('a named reviewer gets only its independent queue, not configuration or own allocation controls',async()=>{
 (api.get as jest.Mock).mockResolvedValue({status:200,data:{userId:reviewer,requests:[{...pending,canReview:true,canCancel:false}],truncated:false}});render(<LicenseScopeActivationsView permissions={['licenses.scopepim.review']} userId={reviewer}/>);
 await userEvent.click(screen.getByRole('button',{name:'Zugewiesene Pool-Aktivierungen laden'}));await screen.findByRole('button',{name:'Pool-Aktivierung genehmigen prüfen'});expect(screen.queryByLabelText('PIM-Pool-ID')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Meine Pool-PIM-Einträge laden'})).not.toBeInTheDocument();
});
test('permission loss discards an opened request without posting its captured authority',async()=>{
 const rendered=render(<LicenseScopeActivationsView {...{permissions,userId}}/>);await open();rendered.rerender(<LicenseScopeActivationsView permissions={[]} userId={userId}/>);expect(screen.queryByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen'})).not.toBeInTheDocument();expect(api.post).not.toHaveBeenCalled();
});
