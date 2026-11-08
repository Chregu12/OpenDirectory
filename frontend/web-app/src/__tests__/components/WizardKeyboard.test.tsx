import { useState } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WizardLayout from '@/components/shared/WizardLayout';
function Fixture() {
  const [open, setOpen] = useState(false);
  return <><button onClick={() => setOpen(true)}>Assistent öffnen</button>{open && <WizardLayout title="Testvorgang" subtitle="Testdaten" color="blue" steps={[{ n: 1, label: 'Prüfen' }]} currentStep={1} onStepChange={() => {}} onClose={() => setOpen(false)} onComplete={() => {}}><label>Begründung<input /></label></WizardLayout>}</>;
}
test('contains keyboard focus, closes on Escape and returns focus to its trigger', async () => {
  render(<Fixture />); const trigger = screen.getByRole('button', { name: 'Assistent öffnen' });
  await userEvent.click(trigger); const dialog = screen.getByRole('dialog', { name: 'Testvorgang' });
  screen.getByRole('button', { name: 'Fertig' }).focus(); await userEvent.tab();
  expect(dialog).toContainElement(document.activeElement as HTMLElement);
  await userEvent.keyboard('{Escape}');
  await waitFor(() => expect(trigger).toHaveFocus());
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});
