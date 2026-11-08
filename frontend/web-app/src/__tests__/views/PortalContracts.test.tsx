import {render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SettingsView from '@/components/views/SettingsView';
import IdentityProviderView from '@/components/views/IdentityProviderView';
import PolicySimulatorView from '@/components/views/PolicySimulatorView';
import {api} from '@/lib/api';
import {ensureSession} from '@/lib/auth';
jest.mock('@/lib/auth',()=>({ensureSession:jest.fn()}));
beforeEach(()=>{jest.clearAllMocks();(ensureSession as jest.Mock).mockResolvedValue({user:{roles:['admin']}});});
test('settings do not report persistence when the returned setting disagrees',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{security:{name:'Sicherheit',description:'Navigation',enabled:true}}});(api.post as jest.Mock).mockResolvedValue({status:200,data:{enabled:true}});const changed=jest.fn();
 render(<SettingsView onModuleChange={changed}/>);await userEvent.setup().click(await screen.findByRole('button',{name:'Modul Sicherheit ausblenden'}));
 expect(await screen.findByRole('alert')).toHaveTextContent('Änderung nicht bestätigt');expect(changed).not.toHaveBeenCalled();
});
test('only a confirmed module setting updates the shared navigation',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{security:{name:'Sicherheit',description:'Navigation',enabled:true}}});(api.post as jest.Mock).mockResolvedValue({status:200,data:{enabled:false}});const changed=jest.fn();
 render(<SettingsView onModuleChange={changed}/>);await userEvent.setup().click(await screen.findByRole('button',{name:'Modul Sicherheit ausblenden'}));await waitFor(()=>expect(changed).toHaveBeenCalledWith('security',false));expect(screen.getByRole('status')).toHaveTextContent('Modulkonfiguration gespeichert');
});
test('identity uses same-origin discovery without invented SaaS accounts or security switches',async()=>{
 const origin=window.location.origin;(api.get as jest.Mock).mockImplementation(async(path:string)=>{if(path.includes('openid-configuration'))return{data:{issuer:origin,authorization_endpoint:origin+'/oauth/authorize',token_endpoint:origin+'/oauth/token',jwks_uri:origin+'/jwks'}};if(path.includes('federation/providers'))return{data:{providers:[]}};throw new Error('SAML not configured');});
 render(<IdentityProviderView/>);expect(await screen.findByText(origin+'/oauth/authorize')).toBeInTheDocument();expect(screen.queryByText('GitHub Enterprise')).not.toBeInTheDocument();expect(screen.queryByRole('switch')).not.toBeInTheDocument();
});
test('technical preview calls the real target-bound read endpoint and remains preview-only',async()=>{
 (api.get as jest.Mock).mockImplementation(async(path:string)=>({data:path.endsWith('/access')?{permissions:['policies.read']}:{previewOnly:true,appliedPoliciesCount:0,effectiveSettings:{},sources:{}}}));
 render(<PolicySimulatorView/>);const user=userEvent.setup();const id='11111111-1111-4111-8111-111111111111';await user.type(await screen.findByRole('textbox',{name:'Kanonische Ziel-ID'}),id);await user.click(screen.getByRole('button',{name:'Vorschau berechnen'}));expect(await screen.findByText('Bestätigte lokale Vorschau')).toBeInTheDocument();expect(api.get).toHaveBeenCalledWith('/api/policies/simulate',{params:{userId:id}});expect(api.post).not.toHaveBeenCalled();
});
