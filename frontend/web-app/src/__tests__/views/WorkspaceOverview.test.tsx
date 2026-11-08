import React from 'react';
import '@testing-library/jest-dom';
import { render, screen } from '@testing-library/react';
import WorkspaceOverview from '@/components/views/WorkspaceOverview';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
jest.mock('@/hooks/useIdentityAccess', () => ({ useIdentityAccess: jest.fn() }));
jest.mock('@/components/views/PIMGroupsPanel', () => ({ __esModule: true, default: () => <section aria-label="PIM-Aufgabengruppen">PIM unabhängig prüfen</section> }));

test.each([false, true])('non-admin start page includes independent PIM activation when directory access unavailable=%s', unavailable => {
  (useIdentityAccess as jest.Mock).mockReturnValue({ access: unavailable ? null : { companyOwner: false, permissions: [] }, unavailable, reload: jest.fn() });
  render(<WorkspaceOverview />);
  expect(screen.getByRole('region', { name: 'PIM-Aufgabengruppen' })).toBeVisible();
  if (unavailable) expect(screen.getByRole('alert')).toHaveTextContent('Aufgabenberechtigungen');
  else expect(screen.getByText('Für deine Sitzung sind keine Verwaltungsaufgaben freigegeben.')).toBeVisible();
});
