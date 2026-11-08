import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicensePoolAssignments from '@/components/views/LicensePoolAssignments';
import { api } from '@/lib/api';
import { directoryUsers } from '@/lib/directoryUsers';
jest.mock('@/lib/directoryUsers', () => ({directoryUsers:{access:jest.fn(),list:jest.fn()},userName:(user:any)=>user.displayName||user.username}));
const pool={id:'pool1',name:'Vendor Product',vendor:'Independent Vendor',total_seats:5,used_seats:1};
const person='11111111-1111-4111-8111-111111111111';
const row={id:'assignment1',license_id:pool.id,assignee_id:person,assignee_name:'Testperson',assignee_type:'user',sources:[{type:'direct',id:'direct1'},{type:'group',id:'engineering'}]};
beforeEach(()=>{jest.clearAllMocks();(directoryUsers.access as jest.Mock).mockResolvedValue({userId:person,demoMode:false,directoryReadProtocol:1,permissions:['users.read']});(directoryUsers.list as jest.Mock).mockResolvedValue({users:[{id:person,username:'fixture',displayName:'Testperson'}],total:1});(api.get as jest.Mock).mockResolvedValue({data:{assignments:[row],total:1}});});
test('removing the direct source does not ask to remove group sources or the whole seat',async()=>{
 (api.delete as jest.Mock).mockResolvedValue({status:204});const changed=jest.fn();render(<LicensePoolAssignments pool={pool} canManage onChanged={changed} onClose={jest.fn()}/>);
 const user=userEvent.setup();await user.click(await screen.findByRole('button',{name:'Direktzuweisung zurücknehmen'}));
 expect(screen.getByText(/Nur die direkte Quelle wird entfernt/)).toBeInTheDocument();
 await user.click(screen.getByRole('button',{name:'Bestätigen'}));
 await waitFor(()=>expect(api.delete).toHaveBeenCalledWith('/api/licenses/pool1/assignments/'+person,{params:{assignee_type:'user'}}));
 expect(changed).toHaveBeenCalledTimes(1);expect(api.post).not.toHaveBeenCalled();
});
test('read-only access shows sources without assignment and revoke controls',async()=>{
 render(<LicensePoolAssignments pool={pool} canManage={false} onChanged={jest.fn()} onClose={jest.fn()}/>);
 expect(await screen.findByText('Direktzuweisung · Über Gruppe engineering')).toBeInTheDocument();
 expect(screen.queryByRole('button',{name:'Zuweisung prüfen'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Direktzuweisung zurücknehmen'})).not.toBeInTheDocument();
});
test('a response for a different pool is an error and cannot enable writes',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{assignments:[{...row,license_id:'different'}]}});
 render(<LicensePoolAssignments pool={pool} canManage onChanged={jest.fn()} onClose={jest.fn()}/>);
 expect(await screen.findByRole('alert')).toHaveTextContent('Pool-Zuweisungen nicht bestätigt');
 expect(screen.getByRole('button',{name:'Zuweisung prüfen'})).toBeDisabled();
});
test('the person picker submits only a canonical person assignment, without a device target',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{assignments:[],total:0}});
 (api.post as jest.Mock).mockResolvedValue({status:201,data:{id:'new-assignment',license_id:pool.id,assignee_id:person,assignee_type:'user'}});
 render(<LicensePoolAssignments pool={pool} canManage onChanged={jest.fn()} onClose={jest.fn()}/>);const user=userEvent.setup();
 await user.selectOptions(await screen.findByRole('combobox',{name:'Person'}),person);await user.click(screen.getByRole('button',{name:'Zuweisung prüfen'}));
 await user.click(screen.getByRole('button',{name:'Bestätigen'}));
 await waitFor(()=>expect(api.post).toHaveBeenCalledWith('/api/licenses/pool1/assign',{assignee_type:'user',assignee_id:person}));
 expect(screen.queryByRole('combobox',{name:'Gerät'})).not.toBeInTheDocument();
});
