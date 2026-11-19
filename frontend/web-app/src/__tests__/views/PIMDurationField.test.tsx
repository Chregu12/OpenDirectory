import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import PIMDurationField from '@/components/views/PIMDurationField';

test('offers ten hours only when the actual assignment permits it', () => {
  const change = jest.fn(); const view = render(<PIMDurationField seconds={3600} maximumSeconds={36000} onChange={change} />);
  fireEvent.change(screen.getByLabelText('Gewünschte Dauer'), { target: { value: '36000' } }); expect(change).toHaveBeenCalledWith(36000);
  view.rerender(<PIMDurationField seconds={3600} maximumSeconds={7200} onChange={change} />);
  expect(screen.queryByRole('option', { name: '10 Stunden' })).not.toBeInTheDocument(); expect(screen.getByRole('option', { name: '2 Stunden' })).toBeInTheDocument();
});
test('keeps short eligibility deadlines and exact seconds instead of rounding up', () => {
  render(<PIMDurationField seconds={61} maximumSeconds={61} onChange={jest.fn()} />);
  expect(screen.getByLabelText('Gewünschte Dauer')).toHaveValue('61'); expect(screen.getByRole('option', { name: '1 Min. 1 Sek.' })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: '15 Minuten' })).not.toBeInTheDocument();
});
test('custom duration emits integer seconds and keeps the actual upper bound', () => {
  const change = jest.fn(); render(<PIMDurationField seconds={3600} maximumSeconds={7200} onChange={change} />);
  fireEvent.change(screen.getByLabelText('Gewünschte Dauer'), { target: { value: 'custom' } });
  expect(change).not.toHaveBeenCalled(); const field = screen.getByLabelText('Dauer (Minuten)'); expect(field).toHaveAttribute('max', '120');
  fireEvent.change(field, { target: { value: '1.5' } }); expect(change).toHaveBeenCalledWith(90);
});
test('the full duration field is disabled during a mutation', () => {
  render(<PIMDurationField seconds={1800} maximumSeconds={7200} disabled onChange={jest.fn()} />);
  expect(screen.getByLabelText('Gewünschte Dauer')).toBeDisabled(); expect(screen.getByLabelText('Dauer (Minuten)')).toBeDisabled();
});
