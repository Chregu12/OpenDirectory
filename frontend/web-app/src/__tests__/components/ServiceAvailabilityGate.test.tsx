import { render, screen } from '@testing-library/react';
import ServiceAvailabilityGate from '@/components/shared/ServiceAvailabilityGate';
import { api } from '@/lib/api';

test('does not mount an unconfigured extension or show sample data', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { configuredServices: ['identity-service'] } });
  render(<ServiceAvailabilityGate service="security-scanner" label="Security Scanner"><p>Scanner controls</p></ServiceAvailabilityGate>);
  expect(await screen.findByText('Erweiterung noch nicht eingerichtet')).toBeInTheDocument();
  expect(screen.queryByText('Scanner controls')).not.toBeInTheDocument();
  expect(screen.queryByText(/Beispieldaten/)).not.toBeInTheDocument();
});

test('mounts a configured real service', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { configuredServices: ['app-store'] } });
  render(<ServiceAvailabilityGate service="app-store" label="App Store"><p>Catalog</p></ServiceAvailabilityGate>);
  expect(await screen.findByText('Catalog')).toBeInTheDocument();
});

test('a failed capability lookup cannot imply a running service', async () => {
  (api.get as jest.Mock).mockRejectedValue(new Error('Offline'));
  render(<ServiceAvailabilityGate service="app-store" label="App Store"><p>Catalog</p></ServiceAvailabilityGate>);
  expect(await screen.findByRole('alert')).toHaveTextContent('Der Einrichtungsstatus konnte nicht geprüft werden.');
  expect(screen.queryByText('Catalog')).not.toBeInTheDocument();
});
