import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SSPRView from '@/components/views/SSPRView';
import { api } from '@/lib/api';
beforeEach(() => jest.clearAllMocks());
test('unavailable history does not retain sample reset requests or positive statistics', async () => {
  (api.get as jest.Mock).mockRejectedValue(new Error('offline'));
  render(<SSPRView />); await userEvent.setup().click(screen.getByRole('button',{name:'Anmeldehistorie'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Anmeldehistorie konnte nicht geladen');
  expect(screen.queryByText(/98%|Sarah|Erfolgsrate/)).not.toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith('/api/auth/audit/login-history?limit=25');
});
test('reset acknowledgement is conditional and never claims email delivery', async () => {
  (api.get as jest.Mock).mockResolvedValue({data:{history:[]}}); (api.post as jest.Mock).mockResolvedValue({status:200,data:{success:true}});
  render(<SSPRView />); const user=userEvent.setup();
  await user.type(screen.getByRole('textbox',{name:'E-Mail-Adresse'}),'fixture@example.test');
  await user.click(screen.getByRole('button',{name:'Rücksetzlink anfordern'}));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/reset-password',{email:'fixture@example.test'}));
  expect(await screen.findByRole('status')).toHaveTextContent('Die Annahme bestätigt keine Zustellung.');
});
