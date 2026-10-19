import React from 'react';
import { act,render,screen,waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RoleReviewsView from '../../components/views/RoleReviewsView';
import { roleReviews } from '../../lib/roleReviews';
import { api } from '../../lib/api';

jest.mock('../../lib/auth',()=>({ startLogin:jest.fn() }));
const operator='11111111-1111-4111-8111-111111111111'; const recipient='22222222-2222-4222-8222-222222222222';
const policyId='33333333-3333-4333-8333-333333333333'; const reviewId='44444444-4444-4444-8444-444444444444'; const targetId='55555555-5555-4555-8555-555555555555';
const access={ subject:'review-operator',userId:operator,demoMode:false,permissions:['reviews.assigned.read','reviews.decide'] };
const policy=(extra={})=>({ id:policyId,role:'license-manager',version:'1',intervalSeconds:86400,windowSeconds:3600,reviewerUserIds:[operator],createdAt:'2026-10-18T10:00:00.000Z',retiredAt:null,protected:false,canRetire:true,requiresFreshMfa:false,...extra });
const row=(extra={})=>({ id:reviewId,policyId,role:'license-manager',targetKind:'assignment' as const,targetId,userId:recipient,version:'1',policyVersion:'1',cycle:'1',dueAt:'2026-10-18T10:00:00.000Z',deadlineAt:'2026-10-18T11:00:00.000Z',baseExpiresAt:null,state:'pending' as const,policyRetired:false,canDecide:true,requiresFreshMfa:false,selfReview:false,...extra });
beforeEach(()=>{
  jest.clearAllMocks();
  (api.get as jest.Mock).mockImplementation(async(url:string)=>({ status:200,data:url.endsWith('/self') ? { userId:operator,reviews:[row()],truncated:false } : url.includes('/policies/') ? { role:'license-manager',policy:null,canCreate:true,requiresFreshMfa:false } : row() }));
  (api.post as jest.Mock).mockResolvedValue({ status:200,data:row({ version:'2',cycle:'2',state:'scheduled',canDecide:false,dueAt:'2026-10-19T10:00:00.000Z',deadlineAt:'2026-10-19T11:00:00.000Z' }) });
});
async function begin() { await screen.findByText('license-manager · Offen'); await userEvent.click(screen.getByRole('button',{ name:'Vergabe behalten prüfen' })); }
async function acknowledge() { await userEvent.type(screen.getByLabelText('Begründung der Bestätigung'),'Independent actual access recertification'); await userEvent.click(screen.getByLabelText('Ziel, Fristen und unabhängige Wirkung geprüft')); }
test('a named independent voter fetches only their queue and confirms exact lease and policy versions',async()=>{
  render(<RoleReviewsView access={access} />); await begin(); expect(api.post).not.toHaveBeenCalled(); const save=screen.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen' }); expect(save).toBeDisabled();
  await acknowledge(); await userEvent.click(save); await screen.findByText(/Bestehende Vergabe bestätigt; nächste Prüfung geplant/);
  expect(api.post).toHaveBeenCalledWith('/api/identity/reviews/'+reviewId+'/decisions',{ decision:'retain',reason:'Independent actual access recertification',acknowledgeScope:true },{ headers:{ 'If-Match':`"od-role-review:${reviewId}:1:1"` } });
  expect((api.get as jest.Mock).mock.calls.every(([url])=>url==='/api/identity/reviews/self')).toBe(true);
});
test.each([{ selfReview:true,canDecide:false },{ state:'expired',canDecide:false },{ state:'scheduled',canDecide:false },{ canDecide:false,requiresFreshMfa:true }])('self, expired, scheduled and insufficient-assurance rows cannot vote: %j',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:{ userId:operator,reviews:[row(extra)],truncated:false } });
  render(<RoleReviewsView access={access} />); await screen.findByRole('article'); expect(screen.queryByRole('button',{ name:'Vergabe behalten prüfen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('a policy reader cannot use a stale response to gain creation or voting controls',async()=>{
  render(<RoleReviewsView access={{ ...access,permissions:['reviews.policies.read','reviews.all.read'] }} />);
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für Zugriffsprüfung'),'license-manager'); await userEvent.click(screen.getByRole('button',{ name:'Prüfrichtlinie laden' })); await screen.findByText('Keine Prüfrichtlinie eingerichtet.');
  expect(screen.queryByRole('button',{ name:'Prüfrichtlinie anlegen prüfen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('a configuration operator explicitly previews deadline effects without profile/role inventory queries',async()=>{
  (api.post as jest.Mock).mockResolvedValue({ status:201,data:policy() });
  render(<RoleReviewsView access={{ ...access,permissions:['reviews.policies.read','reviews.policies.manage','reviews.all.read'] }} />);
  await userEvent.type(screen.getByLabelText('Kanonische Rolle für Zugriffsprüfung'),'license-manager'); await userEvent.click(screen.getByRole('button',{ name:'Prüfrichtlinie laden' }));
  await screen.findByText('Keine Prüfrichtlinie eingerichtet.'); await userEvent.type(screen.getByLabelText('Prüfer-UUIDs (eine je Zeile)'),operator);
  await userEvent.type(screen.getByLabelText('Begründung der Prüfrichtlinie'),'Independent actual access recertification'); await userEvent.click(screen.getByRole('button',{ name:'Prüfrichtlinie anlegen prüfen' }));
  expect(api.post).not.toHaveBeenCalled(); await userEvent.click(screen.getByLabelText('Ziel, Fristen und unabhängige Wirkung geprüft')); await userEvent.click(screen.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen' }));
  await screen.findByText(/Prüfrichtlinie bestätigt/); expect((api.get as jest.Mock).mock.calls.every(([url])=>url==='/api/identity/reviews/policies/license-manager')).toBe(true);
});
test('lost authority closes stale confirmation before a different actor can reuse it',async()=>{
  const view=render(<RoleReviewsView access={access} />); await begin();
  view.rerender(<RoleReviewsView access={{ ...access,subject:'reader',permissions:['reviews.all.read'] }} />);
  await waitFor(()=>expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()); expect(api.post).not.toHaveBeenCalled();
});
test('a late receipt cannot announce success under another actor',async()=>{
  let finish!: (response:any)=>void; (api.post as jest.Mock).mockImplementation(()=>new Promise(resolve=>{ finish=resolve; }));
  const view=render(<RoleReviewsView access={access} />); await begin(); await acknowledge(); await userEvent.click(screen.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen' }));
  view.rerender(<RoleReviewsView access={{ ...access,subject:'new-reader',permissions:['reviews.all.read'] }} />);
  await act(async()=>finish({ status:200,data:row({ version:'2',cycle:'2',state:'scheduled',canDecide:false,dueAt:'2026-10-19T10:00:00.000Z',deadlineAt:'2026-10-19T11:00:00.000Z' }) }));
  expect(screen.queryByText(/Bestehende Vergabe bestätigt/)).not.toBeInTheDocument();
});
test('a retirement/version conflict cannot silently become an unbounded retain or a blind retry',async()=>{
  (api.post as jest.Mock).mockRejectedValue({ response:{ status:412,data:{ error:'review_changed' } } });
  render(<RoleReviewsView access={access} />); await begin(); await acknowledge(); await userEvent.click(screen.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen' }));
  await screen.findByText(/Prüfung oder Richtlinie wurde geändert/); expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen' })).toBeDisabled();
});
test.each([{ canDecide:true,state:'expired' },{ version:'0' },{ policyVersion:'0' },{ ignored:true },{ policyId:targetId },{ cycle:'0' }])('malformed, partial or mismatched decision receipts cannot become success: %j',async extra=>{
  const retained=row({ version:'2',cycle:'2',state:'scheduled',canDecide:false,dueAt:'2026-10-19T10:00:00.000Z',deadlineAt:'2026-10-19T11:00:00.000Z',...extra });
  (api.post as jest.Mock).mockResolvedValue({ status:200,data:retained });
  await expect(roleReviews.decide(row(),{ decision:'retain',reason:'Independently reviewed decision',acknowledgeScope:true })).rejects.toThrow();
});
test('a changed retirement state and partial HTTP success cannot be treated as confirmation',async()=>{
  for(const response of [{ status:207,data:row() },{ status:200,data:row({ version:'2',cycle:'2',policyVersion:'2',policyRetired:true,state:'exempt',canDecide:false,dueAt:null,deadlineAt:null }) }]) {
    (api.post as jest.Mock).mockResolvedValue(response); await expect(roleReviews.decide(row(),{ decision:'retain',reason:'Independently reviewed decision',acknowledgeScope:true })).rejects.toThrow();
  }
});
