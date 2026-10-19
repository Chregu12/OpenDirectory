import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import ServicePrincipalListColumn from '../../components/views/ServicePrincipalListColumn';
import { qaGet } from '../../lib/quickActionsApi';

jest.mock('../../lib/quickActionsApi', () => ({ qaGet: jest.fn(), qaPost: jest.fn(), qaDelete: jest.fn() }));

function backend(permissions: string[]) {
  (qaGet as jest.Mock).mockImplementation(async (path: string) => path.endsWith('/access')
    ? { subject: 'operator', permissions }
    : { success: true, data: [{ clientId: 'app-id', name: 'Inventory Application', permissions: ['directory.read'] }] });
}

beforeEach(() => { jest.clearAllMocks(); });

test('a reader sees the canonical data envelope without administrative controls', async () => {
  backend(['applications.read']);
  render(<ServicePrincipalListColumn selectedId={null} onSelect={jest.fn()} onCreateNew={jest.fn()} />);
  expect(await screen.findByText('Inventory Application')).toBeInTheDocument();
  expect(screen.queryByTitle('New Service Principal')).not.toBeInTheDocument();
  expect(screen.queryByTitle('Rotate secret')).not.toBeInTheDocument();
  expect(screen.queryByTitle('Delete')).not.toBeInTheDocument();
});

test('a credential operator does not inherit application deletion or creation', async () => {
  backend(['applications.read', 'applications.credentials.rotate']);
  render(<ServicePrincipalListColumn selectedId={null} onSelect={jest.fn()} onCreateNew={jest.fn()} />);
  expect(await screen.findByTitle('Rotate secret')).toBeInTheDocument();
  expect(screen.queryByTitle('Delete')).not.toBeInTheDocument();
  expect(screen.queryByTitle('New Service Principal')).not.toBeInTheDocument();
});

test('an ordinary user does not request the administrative account list', async () => {
  backend([]);
  render(<ServicePrincipalListColumn selectedId={null} onSelect={jest.fn()} />);
  await waitFor(() => expect(qaGet).toHaveBeenCalledWith('/api/quick/access'));
  expect(qaGet).not.toHaveBeenCalledWith('/api/quick/service-principals');
});
