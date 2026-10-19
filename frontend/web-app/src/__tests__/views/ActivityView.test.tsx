import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import ActivityView from '@/components/views/ActivityView';

const originalFetch = global.fetch;
const event = (changes = {}) => ({ id: 'actual-event', timestamp: '2026-10-19T09:00:00Z', event: 'Actual policy update', user: 'actual-user', source: 'Policy', severity: 'success', ...changes });
const response = (data: unknown) => ({ ok: true, json: async () => data });
const summary = (label: string) => screen.getByText(label).nextElementSibling;

beforeEach(() => { global.fetch = jest.fn(); });
afterAll(() => { global.fetch = originalFetch; });

test('counts distinct actual actors without an ES2015 iterator spread', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response({ events: [
    event(), event({ id: 'second-event', severity: 'error' }),
    event({ id: 'third-event', user: 'other-user', severity: 'warning' }),
  ] }));
  render(<ActivityView />);
  await screen.findByText('other-user');
  expect(summary('LOADED EVENTS')).toHaveTextContent(/^3$/);
  expect(summary('ACTIVE USERS')).toHaveTextContent(/^2$/);
  expect(summary('ERRORS')).toHaveTextContent(/^1$/);
  expect(summary('WARNINGS')).toHaveTextContent(/^1$/);
  expect(global.fetch).toHaveBeenCalledWith('/api/audit/events?limit=100');
  expect(screen.queryByText(/12%|EVENTS TODAY/)).not.toBeInTheDocument();
  expect(screen.queryByText('admin@corp.local')).not.toBeInTheDocument();
});

test('accepts actual backend data envelopes and does not invent absent actors or severity', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response({ success: true, data: [
    { id: 0, event_time: '2026-10-19T09:00:00Z', operation: 'Actual policy update' },
  ] }));
  render(<ActivityView />);
  await screen.findByText('Actual policy update');
  expect(summary('ACTIVE USERS')).toHaveTextContent(/^0$/);
  expect(screen.getByText('unknown')).toBeInTheDocument();
  expect(screen.queryByText('system')).not.toBeInTheDocument();
});

test.each([[], { events: [] }, { success: true, data: [] }])('keeps a genuine empty audit response empty: %j', async data => {
  (global.fetch as jest.Mock).mockResolvedValue(response(data));
  render(<ActivityView />);
  await screen.findByText('No events found');
  expect(summary('LOADED EVENTS')).toHaveTextContent(/^0$/);
  expect(summary('ACTIVE USERS')).toHaveTextContent(/^0$/);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test.each([
  null, {}, { events: {} }, { success: false, data: [] }, [null],
  [event({ id: undefined })], [event({ timestamp: undefined })], [event({ timestamp: 'invalid' })],
  [event({ event: {} })], [event({ user: {} })], [event({ source: 42 })],
  [event({ severity: {} })], [event(), event()],
])('rejects unusable audit data %j without fabricated records', async data => {
  (global.fetch as jest.Mock).mockResolvedValue(response(data));
  render(<ActivityView />);
  await screen.findByRole('alert');
  expect(summary('LOADED EVENTS')).toHaveTextContent(/^—$/);
  expect(screen.queryByText('Actual policy update')).not.toBeInTheDocument();
  expect(screen.queryByText('admin@corp.local')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Export' })).toBeDisabled();
});

test.each(['HTTP', 'network', 'JSON'])('shows audit unavailability on %s failure', async failure => {
  const fetchMock = global.fetch as jest.Mock;
  if (failure === 'HTTP') fetchMock.mockResolvedValue({ ok: false, status: 503 });
  else if (failure === 'network') fetchMock.mockRejectedValue(new Error('offline'));
  else fetchMock.mockResolvedValue({ ok: true, json: async () => { throw new SyntaxError('Invalid JSON'); } });
  render(<ActivityView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Activity is unavailable');
  expect(summary('ACTIVE USERS')).toHaveTextContent(/^—$/);
});

test('clears stale events on failure and recovers on explicit refresh', async () => {
  (global.fetch as jest.Mock).mockResolvedValueOnce(response([event()]))
    .mockResolvedValueOnce({ ok: false, status: 503 }).mockResolvedValueOnce(response([]));
  render(<ActivityView />);
  await screen.findByText('Actual policy update');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByRole('alert');
  expect(screen.queryByText('Actual policy update')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByText('No events found');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
