import React from 'react';
import '@testing-library/jest-dom';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CompanyAutomationView from '@/components/views/CompanyAutomationView';
import { companyAutomation } from '@/lib/companyAutomation';
import { directoryUsers } from '@/lib/directoryUsers';
import { companyLicenseGroups } from '@/lib/companyLicenseGroups';
import { companyGroupRules } from '@/lib/companyGroupRules';
jest.mock('@/lib/companyGroupRules',()=>({companyGroupRules:{get:jest.fn()}}));
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { access: jest.fn() } }));
jest.mock('@/lib/companyAutomation', () => ({ automationActions: ['directory.users.export', 'directory.groups.export', 'directory.ous.export','licenses.groups.reconcile','directory.groups.reconcile'], licenseAutomationAction: 'licenses.groups.reconcile', groupRuleAutomationAction:'directory.groups.reconcile', isReconciliationAction:(value:string)=>['licenses.groups.reconcile','directory.groups.reconcile'].includes(value), companyAutomation: { grants: jest.fn(), enrollment: jest.fn(), approve: jest.fn(), jobs: jest.fn(), schedules: jest.fn(), queue: jest.fn(), revoke: jest.fn(), changeJob: jest.fn(), disable: jest.fn(), history: jest.fn(), licenseReport: jest.fn(), groupReport:jest.fn() } }));
jest.mock('@/lib/companyLicenseGroups', () => ({ companyLicenseGroups: { inspect: jest.fn() } }));
const id = (n: number) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const principal = { kind: 'owner', userId: id(1), tenantId: id(2) };
const grant: any = { id: id(3), tenantId: id(2), clientId: 'worker', clientRevision: '1', actions: ['directory.users.export'], expiresAt: '2099-10-22T10:00:00.000Z', status: 'active', revision: '1' };
beforeEach(() => {
  jest.clearAllMocks(); (directoryUsers.access as jest.Mock).mockResolvedValue({ userId: id(1), demoMode: false, companyOwner: true });
  (companyAutomation.grants as jest.Mock).mockResolvedValue({ principal, grants: [grant], page: 1, limit: 25, total: 1 });
  (companyAutomation.jobs as jest.Mock).mockResolvedValue({ jobs: [], total: 0 }); (companyAutomation.schedules as jest.Mock).mockResolvedValue({ schedules: [], total: 0 });
  (companyAutomation.enrollment as jest.Mock).mockResolvedValue({ principal, id: id(4), clientId: 'worker', clientRevision: '1', name: 'Export worker', expiresAt: '2099-10-22T10:00:00.000Z' });
  (companyAutomation.queue as jest.Mock).mockResolvedValue({}); (companyAutomation.approve as jest.Mock).mockResolvedValue(grant); (companyAutomation.revoke as jest.Mock).mockResolvedValue({ ...grant, status: 'revoked' });
});
async function ready() { await waitFor(() => expect(screen.getByLabelText('Automationsaktion')).toBeEnabled()); }
test('shows only own actual grants and never starts jobs just by opening the page', async () => {
  render(<CompanyAutomationView/>); await ready(); expect(screen.getByText(/Worker auf deinem Runner starten/)).toBeInTheDocument(); expect(companyAutomation.queue).not.toHaveBeenCalled();
});
test('an ordinary principal sees no approval or fabricated workflow data', async () => {
  (directoryUsers.access as jest.Mock).mockResolvedValue({ userId: id(1), demoMode: false, companyOwner: false }); render(<CompanyAutomationView/>); await screen.findByRole('alert'); expect(companyAutomation.grants).not.toHaveBeenCalled();
});
test('queues one actual export and reports only durable queueing', async () => {
  render(<CompanyAutomationView/>); await ready(); fireEvent.change(screen.getByLabelText('Automationsaktion'), { target: { value: 'directory.users.export' } });
  fireEvent.click(screen.getByRole('button', { name: 'Exportjob einreihen' })); await screen.findByText(/Job dauerhaft eingereiht/);
  expect(companyAutomation.queue).toHaveBeenCalledWith(grant, 'directory.users.export', 'json', principal, undefined, undefined);
});
test('owner approval displays the actual app generation and requires an explicit confirmation', async () => {
  render(<CompanyAutomationView/>); await ready(); fireEvent.change(screen.getByLabelText('App-Anmeldungs-ID'), { target: { value: id(4) } });
  fireEvent.click(screen.getByRole('button', { name: 'App-Anmeldung prüfen' })); await screen.findByText(/Von der App angegebener Name/);
  fireEvent.click(screen.getByLabelText('Benutzer exportieren')); fireEvent.change(screen.getByLabelText('Automationsfreigabe begründen'), { target: { value: 'Eigene Benutzer ausdrücklich exportieren' } });
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte App-Rechte bestätigen' })); expect(companyAutomation.approve).not.toHaveBeenCalled();
  expect(screen.getByRole('dialog')).toHaveTextContent('Generation 1'); fireEvent.click(screen.getByRole('button', { name: 'Verbindlich bestätigen' }));
  await waitFor(() => expect(companyAutomation.approve).toHaveBeenCalledTimes(1));
});
test('revocation is separate from selection and preserves the concrete confirmation', async () => {
  render(<CompanyAutomationView/>); await ready(); fireEvent.click(screen.getByRole('button', { name: 'App-Freigabe widerrufen' })); expect(companyAutomation.revoke).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Verbindlich bestätigen' })); await waitFor(() => expect(companyAutomation.revoke).toHaveBeenCalledWith(grant, principal));
});
test('license jobs require a checked own group link and persist that exact link in a schedule', async () => {
 const licensed = { ...grant, actions: ['licenses.groups.reconcile'] };
 (companyAutomation.grants as jest.Mock).mockResolvedValue({ principal, grants: [licensed], page: 1, limit: 25, total: 1 });
 (companyLicenseGroups.inspect as jest.Mock).mockResolvedValue({ rule: { id: id(8), tenantId: id(2), groupId: id(9), poolId: id(10), status: 'active' }, groupName: 'Engineering', eligibleMembers: 4 });
 render(<CompanyAutomationView/>); await ready(); fireEvent.change(screen.getByLabelText('Automationsaktion'), { target: { value: 'licenses.groups.reconcile' } });
 expect(screen.queryByLabelText('Exportformat')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Lizenzabgleich einreihen' })).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Lizenzgruppen-Verknüpfungs-ID'), { target: { value: id(8) } });
 fireEvent.click(screen.getByRole('button', { name: 'Lizenzgruppe prüfen' })); await screen.findByText(/Gruppe: Engineering/);
 expect(companyLicenseGroups.inspect).toHaveBeenCalledWith(id(8), { actorUserId: id(1), tenantId: id(2) });
 fireEvent.click(screen.getByRole('button', { name: 'Zeitplan erstellen' })); await waitFor(() => expect(companyAutomation.queue).toHaveBeenCalledWith(licensed, 'licenses.groups.reconcile', 'json', principal, 60, id(8)));
});
test('license write consent states assignment and removal before approval', async () => {
 render(<CompanyAutomationView/>); await ready(); fireEvent.change(screen.getByLabelText('App-Anmeldungs-ID'), { target: { value: id(4) } });
 fireEvent.click(screen.getByRole('button', { name: 'App-Anmeldung prüfen' })); await screen.findByText(/Von der App angegebener Name/);
 fireEvent.click(screen.getByLabelText('Gruppenlizenzen zuweisen und entziehen')); fireEvent.change(screen.getByLabelText('Automationsfreigabe begründen'), { target: { value: 'Eigene Lizenzen ausdrücklich automatisch abgleichen' } });
 fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte App-Rechte bestätigen' }));
 expect(screen.getByRole('dialog')).toHaveTextContent('Lizenzsitze anhand bestehender Gruppenverknüpfungen zuweisen und entziehen'); expect(companyAutomation.approve).not.toHaveBeenCalled();
});
test('group-rule automation requires a checked own saved rule and binds the actual group ID in the schedule',async()=>{
 const grouped={...grant,actions:['directory.groups.reconcile']};(companyAutomation.grants as jest.Mock).mockResolvedValue({principal,grants:[grouped],page:1,limit:25,total:1});
 (companyGroupRules.get as jest.Mock).mockResolvedValue({groupId:id(8),tenantId:id(2),rule:{revision:'3',enabled:true}});
 render(<CompanyAutomationView/>);await ready();fireEvent.change(screen.getByLabelText('Automationsaktion'),{target:{value:'directory.groups.reconcile'}});
 expect(screen.queryByLabelText('Exportformat')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Gruppenregel-Abgleich einreihen'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Gruppenregel-Gruppen-ID'),{target:{value:id(8)}});fireEvent.click(screen.getByRole('button',{name:'Gruppenregel prüfen'}));await screen.findByText(/Gespeicherte Regelversion 3/);
 expect(companyGroupRules.get).toHaveBeenCalledWith(id(8),id(1));fireEvent.click(screen.getByRole('button',{name:'Zeitplan erstellen'}));await waitFor(()=>expect(companyAutomation.queue).toHaveBeenCalledWith(grouped,'directory.groups.reconcile','json',principal,60,id(8)));
});
test('owner explicitly enables a checked change subscription without a timer or an implicit execution',async()=>{
 const grouped={...grant,actions:['directory.groups.reconcile']};(companyAutomation.grants as jest.Mock).mockResolvedValue({principal,grants:[grouped],page:1,limit:25,total:1});(companyGroupRules.get as jest.Mock).mockResolvedValue({groupId:id(8),tenantId:id(2),rule:{revision:'3',enabled:true}});
 render(<CompanyAutomationView/>);await ready();fireEvent.change(screen.getByLabelText('Automationsaktion'),{target:{value:'directory.groups.reconcile'}});expect(screen.getByRole('button',{name:'Bei Quellenänderungen abgleichen'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Gruppenregel-Gruppen-ID'),{target:{value:id(8)}});fireEvent.click(screen.getByRole('button',{name:'Gruppenregel prüfen'}));await screen.findByText(/Gespeicherte Regelversion 3/);expect(companyAutomation.queue).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Bei Quellenänderungen abgleichen'}));await waitFor(()=>expect(companyAutomation.queue).toHaveBeenCalledWith(grouped,'directory.groups.reconcile','json',principal,undefined,id(8),true));
});
