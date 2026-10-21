import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import BlueprintsView from '@/components/views/BlueprintsView';
import IdentityProviderView from '@/components/views/IdentityProviderView';
import { api } from '@/lib/api';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
jest.mock('@/components/views/AppRegistrationsView', () => () => null);
jest.mock('react-hot-toast', () => ({ __esModule: true, default: { error: jest.fn(), success: jest.fn() } }));

test('ADE failure cannot be mistaken for empty inventory or completed enrollment', async () => {
  (api.get as jest.Mock).mockImplementation((url: string) => url === '/api/mdm/dep/devices'
    ? Promise.reject({ response: { status: 503, data: { error: 'apple_ade_not_configured' } } })
    : Promise.resolve({ data: { blueprints: [] } }));
  render(<BlueprintsView />);
  fireEvent.click(screen.getByRole('button', { name: /ADE Geräte/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('eine Registrierung oder Zuweisung ist nicht bestätigt');
  expect(screen.getByText('Apple-Registrierung nicht verfügbar')).toBeInTheDocument();
  expect(screen.queryByText('Keine ADE-Geräte vorhanden')).not.toBeInTheDocument();
  expect(screen.getByText(/vorläufige Frist von 30 Tagen/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Blueprint zuweisen' })).not.toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});

test('SAML view describes the supported flow without claiming active demo connections or logout', () => {
  render(<IdentityProviderView />);
  fireEvent.click(screen.getByRole('button', { name: 'SAML 2.0' }));
  expect(screen.getByText(/SP-initiierte AuthnRequests und Single Logout sind noch nicht verfügbar/)).toBeInTheDocument();
  expect(screen.getByText(/Diese Ansicht bestätigt keine eingerichtete Verbindung/)).toBeInTheDocument();
  expect(screen.queryByText('GitLab')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Service Provider verbinden' })).not.toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Metadaten beim Identity Provider öffnen' })).toHaveAttribute('href', expect.stringContaining('/saml/metadata'));
});
