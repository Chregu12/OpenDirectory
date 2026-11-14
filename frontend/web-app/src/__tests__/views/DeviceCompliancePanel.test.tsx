import React from 'react';
import {render,screen} from '@testing-library/react';
import DeviceCompliancePanel from '@/components/views/DeviceCompliancePanel';
import {complianceAccess} from '@/lib/deviceCompliance';
jest.mock('@/lib/deviceCompliance',()=>({complianceAccess:jest.fn(),readComplianceReport:jest.fn(),readComplianceHistory:jest.fn(),complianceLabels:{},complianceError:()=> 'Keine Berechtigung für Geräte-Compliance.'}));
test('independent compliance denial clears this panel without removing authorized inventory access',async()=>{
 (complianceAccess as jest.Mock).mockRejectedValue({response:{status:403}});const security=jest.fn();render(<DeviceCompliancePanel deviceId="11111111-1111-4111-8111-111111111111" onSecurityError={security}/>);
 expect(await screen.findByRole('alert')).toHaveTextContent('Keine Berechtigung');expect(security).not.toHaveBeenCalled();expect(screen.queryByText('Letzte protokollierte Bewertung')).not.toBeInTheDocument();
});
