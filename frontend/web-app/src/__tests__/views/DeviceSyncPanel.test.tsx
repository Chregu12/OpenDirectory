import React from 'react';
import {act,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {api} from '@/lib/api';
import DeviceSyncPanel from '@/components/views/DeviceSyncPanel';
jest.mock('@/lib/api',()=>({api:{get:jest.fn(),post:jest.fn()}}));
const actor='11111111-1111-4111-8111-111111111111',tenant='22222222-2222-4222-8222-222222222222',id='33333333-3333-4333-8333-333333333333';
const device:any={id,tenantId:tenant,revision:'1'};
const page={schemaVersion:1,syncProtocol:1,actorUserId:actor,tenantId:tenant,deviceId:id,checkedAt:'2026-11-14T12:00:00.000Z',connectionEtag:`"device-sync-generation-${id}-${'a'.repeat(32)}"`,page:1,limit:10,total:0,requests:[]};
beforeEach(()=>{jest.resetAllMocks();(api.get as jest.Mock).mockResolvedValue({status:200,data:page});});
test('read-only operators can inspect state without issuing or cancelling sync',async()=>{render(<DeviceSyncPanel device={device} actor={actor} canManage={false} disabled={false} onSecurityError={jest.fn()} onChanged={jest.fn()}/>);await screen.findByText('Noch keine Synchronisierung angefordert.');expect(screen.queryByRole('button',{name:'Synchronisierung anfordern'})).not.toBeInTheDocument();expect(api.post).not.toHaveBeenCalled();});
test('session loss removes dialog and ignores a late accepted write',async()=>{
 let complete:(value:any)=>void=()=>{};(api.post as jest.Mock).mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));const changed=jest.fn(),busy=jest.fn();render(<DeviceSyncPanel device={device} actor={actor} canManage disabled={false} onSecurityError={jest.fn()} onChanged={changed} onBusy={busy}/>);
 const start=await screen.findByRole('button',{name:'Synchronisierung anfordern'});await waitFor(()=>expect(start).toBeEnabled());fireEvent.click(start);const dialog=within(screen.getByRole('alertdialog'));fireEvent.change(dialog.getByLabelText('Begründung'),{target:{value:'Read actual current hardware observations'}});fireEvent.click(dialog.getByRole('button',{name:'Bestätigen'}));await waitFor(()=>expect(api.post).toHaveBeenCalledTimes(1));
 act(()=>window.dispatchEvent(new Event('od:session-error')));expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();await act(async()=>{complete({status:201,data:{}});});expect(changed).not.toHaveBeenCalled();expect(busy.mock.calls).toEqual([[true],[false]]);expect(screen.queryByText('Synchronisierung angefordert.',{exact:false})).not.toBeInTheDocument();expect(screen.getByRole('alert')).toHaveTextContent('nicht mehr gültig');
});
