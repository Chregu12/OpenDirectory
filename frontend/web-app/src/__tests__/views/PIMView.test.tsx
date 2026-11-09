import React from 'react';
import '@testing-library/jest-dom';
import { fireEvent, render, screen } from '@testing-library/react';
import PIMView from '@/components/views/PIMView';
jest.mock('@/components/views/PIMGroupsPanel', () => ({ __esModule: true, default: ({ management }: { management: boolean }) => <section aria-label="PIM-Aufgabengruppen">{management ? 'Gruppenverwaltung verfügbar' : 'Eigene Rollen'}</section> }));
jest.mock('@/components/views/PIMAdvancedView', () => ({ __esModule: true, default: () => <section aria-label="Erweiterte Rollenverwaltung">Weitere Rollen</section> }));
test('starts with task assignments and keeps advanced forms unmounted', () => {
  render(<PIMView />);
  expect(screen.getByRole('heading', { name: 'Privileged Identity Management' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'PIM-Aufgabengruppen' })).toHaveTextContent('Gruppenverwaltung verfügbar');
  expect(screen.queryByRole('region', { name: 'Erweiterte Rollenverwaltung' })).not.toBeInTheDocument();
});
test('advanced role tools load only after an explicit selection', () => {
  render(<PIMView />); fireEvent.click(screen.getByRole('button', { name: 'Weitere Rollen und Richtlinien' }));
  expect(screen.getByRole('region', { name: 'Erweiterte Rollenverwaltung' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Weitere Rollen und Richtlinien schließen' }));
  expect(screen.queryByRole('region', { name: 'Erweiterte Rollenverwaltung' })).not.toBeInTheDocument();
});
