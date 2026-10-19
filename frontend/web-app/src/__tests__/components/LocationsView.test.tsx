import React from 'react';
import { render, screen } from '@testing-library/react';
import LocationsView from '@/components/views/LocationsView';
import { api } from '@/lib/api';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));

test('shows unavailable location management instead of invented sites and device statistics', () => {
  render(<LocationsView />);
  expect(screen.getByRole('heading', { name: 'Standorte', level: 1 })).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Standortverwaltung noch nicht verfügbar');
  expect(screen.getByRole('status')).toHaveTextContent('keine echten Standortdaten geladen');
  expect(screen.queryByText('Headquarters')).not.toBeInTheDocument();
  expect(screen.queryByText('Berlin Office')).not.toBeInTheDocument();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
});

test('does not offer fake create, save or export actions without a backend', () => {
  render(<LocationsView />);
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  expect(api.get).not.toHaveBeenCalled();
  expect(api.post).not.toHaveBeenCalled();
});
