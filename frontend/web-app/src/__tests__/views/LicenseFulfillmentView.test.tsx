import React from 'react';
import { render,screen,waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicenseFulfillmentView from '../../components/views/LicenseFulfillmentView';
import { licenseFulfillment } from '../../lib/licenseFulfillment';
import { api } from '../../lib/api';
const licenseId='11111111-1111-4111-8111-111111111111'; const userId='22222222-2222-4222-8222-222222222222'; const id='33333333-3333-4333-8333-333333333333';
const permissions=['licenses.fulfillment.read','licenses.fulfillment.retry','licenses.fulfillment.adopt'];
const row=(extra={})=>({ id,licenseId,userId,objectId:userId,connectorId:licenseId,version:'1',desired:true,localDesired:true,eligibilityBlocked:false,status:'unknown',owned:false,paused:false,
  observation:{ present:true,direct:true,active:true,plansMatch:true,inherited:false,accountEnabled:true },checkedAt:'2026-10-18T12:00:00.000Z',error:'uncertain_write_requires_review',canRetry:true,canAdopt:true,adoptionPurpose:'fulfill',...extra });
beforeEach(()=>{ jest.clearAllMocks(); (api.get as jest.Mock).mockResolvedValue({ status:200,data:row() }); (api.post as jest.Mock).mockResolvedValue({ status:200,data:row({ version:'2',status:'pending',error:null,canRetry:false }) }); });
async function load() {
  await userEvent.type(screen.getByLabelText('Lokale Lizenz-ID für Provider-Status'),licenseId); await userEvent.type(screen.getByLabelText('Verzeichnis-ID für Provider-Status'),userId);
  await userEvent.click(screen.getByRole('button',{ name:'Provider-Status prüfen' })); await screen.findByText(/Ergebnis unklar/);
}
test('reads only a known license/user pair and never equates a local assignment or unknown vendor receipt with provisioned access',async()=>{
  render(<LicenseFulfillmentView permissions={permissions} subject="operator" />); await load();
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.get).toHaveBeenCalledWith(`/api/licenses/fulfillment/targets/${licenseId}/${userId}`,{ signal:expect.any(AbortSignal) });
  expect(screen.queryByText('Zuletzt beobachteter Sollstand bestätigt')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('retry requires independent acknowledgement, a reason and the exact target version; success means queued only',async()=>{
  render(<LicenseFulfillmentView permissions={permissions} subject="operator" />); await load(); await userEvent.click(screen.getByRole('button',{ name:'Erneute Prüfung vorbereiten' }));
  expect(screen.getByRole('button',{ name:'Provider-Prüfentscheidung speichern' })).toBeDisabled();
  await userEvent.type(screen.getByLabelText('Begründung der Provider-Prüfentscheidung'),'Reviewed possible previous remote mutation'); await userEvent.click(screen.getByRole('checkbox'));
  await userEvent.click(screen.getByRole('button',{ name:'Provider-Prüfentscheidung speichern' })); await screen.findByText(/Dies bestätigt keine externe Bereitstellung/);
  expect(screen.getByText('Auftrag vorgemerkt')).toBeInTheDocument(); expect(api.post).toHaveBeenCalledWith(`/api/licenses/fulfillment/targets/${id}/retry`,{ reason:'Reviewed possible previous remote mutation',acknowledgeUncertainOutcome:true },{ headers:{ 'If-Match':`"od-fulfillment:targets:${id}:1"` } });
});
test('a reader cannot activate stale server-advertised retry or adoption controls',async()=>{
  render(<LicenseFulfillmentView permissions={['licenses.fulfillment.read']} subject="reader" />); await load();
  expect(screen.queryByRole('button',{ name:'Erneute Prüfung vorbereiten' })).not.toBeInTheDocument(); expect(screen.queryByRole('button',{ name:'Vorhandene Direktzuweisung übernehmen' })).not.toBeInTheDocument();
});
test('cleanup adoption explicitly acknowledges an already withdrawn uncertain grant and still reports only queued work',async()=>{
  const cleanup=row({ desired:false,localDesired:false,adoptionPurpose:'cleanup',observation:{ present:true,direct:true,active:false,plansMatch:true,inherited:false,accountEnabled:false } });
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:cleanup }); (api.post as jest.Mock).mockResolvedValue({ status:200,data:{ ...cleanup,version:'2',status:'pending',owned:true,error:null,canRetry:false,canAdopt:false,adoptionPurpose:null } });
  render(<LicenseFulfillmentView permissions={permissions} subject="operator" />); await load(); await userEvent.click(screen.getByRole('button',{ name:'Übernahme zur Bereinigung vorbereiten' }));
  expect(screen.getByText(/es wird kein neuer Zugriff erteilt/)).toBeInTheDocument(); await userEvent.type(screen.getByLabelText('Begründung der Provider-Prüfentscheidung'),'Reviewed withdrawn uncertain vendor assignment'); await userEvent.click(screen.getByRole('checkbox')); await userEvent.click(screen.getByRole('button',{ name:'Provider-Prüfentscheidung speichern' }));
  await screen.findByText(/Dies bestätigt keine externe Bereitstellung/); expect(screen.getByText('Auftrag vorgemerkt')).toBeInTheDocument(); expect(screen.queryByText('Zuletzt beobachteter Sollstand bestätigt')).not.toBeInTheDocument();
});
test('permission loss clears an old confirmation without issuing its write',async()=>{
  const view=render(<LicenseFulfillmentView permissions={permissions} subject="operator" />); await load(); await userEvent.click(screen.getByRole('button',{ name:'Erneute Prüfung vorbereiten' }));
  view.rerender(<LicenseFulfillmentView permissions={['licenses.fulfillment.read']} subject="operator" />); await waitFor(()=>expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()); expect(api.post).not.toHaveBeenCalled();
});
test('an unconfirmed mutation is not retried or called successful',async()=>{
  (api.post as jest.Mock).mockRejectedValue({ response:{ status:412 } }); render(<LicenseFulfillmentView permissions={permissions} subject="operator" />); await load();
  await userEvent.click(screen.getByRole('button',{ name:'Erneute Prüfung vorbereiten' })); await userEvent.type(screen.getByLabelText('Begründung der Provider-Prüfentscheidung'),'Reviewed current uncertain provider state'); await userEvent.click(screen.getByRole('checkbox')); await userEvent.click(screen.getByRole('button',{ name:'Provider-Prüfentscheidung speichern' }));
  await screen.findByText(/Der Auftrag wurde inzwischen geändert/); expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('button',{ name:'Provider-Prüfentscheidung speichern' })).toBeDisabled();
});
test.each([{ status:'confirmed',owned:false },{ status:'confirmed',desired:false },{ status:'confirmed',observation:null },{ version:'0' },{ desired:'true' },{ secret:'not-an-allowed-field' }])('partial or contradictory provider metadata %j cannot become a green state',async extra=>{
  (api.get as jest.Mock).mockResolvedValue({ status:200,data:row(extra) }); await expect(licenseFulfillment.get(licenseId,userId)).rejects.toThrow();
});
test.each([{ status:207,data:row({ version:'2',status:'pending' }) },{ status:200,data:row({ status:'pending' }) },{ status:200,data:row({ version:'2',status:'confirmed',owned:true }) }])('a partial, unchanged or falsely fulfilled control receipt cannot mean success: %j',async response=>{
  (api.post as jest.Mock).mockResolvedValue(response); await expect(licenseFulfillment.resolve(row() as any,'retry','Reviewed target operation state')).rejects.toThrow();
});
