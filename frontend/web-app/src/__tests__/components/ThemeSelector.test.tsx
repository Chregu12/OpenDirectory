import { act, fireEvent, render, screen } from '@testing-library/react';
import ThemeSelector from '@/components/layout/ThemeSelector';

let media: { matches: boolean; addEventListener: jest.Mock; removeEventListener: jest.Mock };
let listeners: Set<() => void>;

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  listeners = new Set();
  media = { matches: false, addEventListener: jest.fn((_, listener) => listeners.add(listener)),
    removeEventListener: jest.fn((_, listener) => listeners.delete(listener)) };
  window.matchMedia = jest.fn().mockReturnValue(media);
});

afterEach(() => jest.restoreAllMocks());

function systemDark(matches: boolean) {
  act(() => { media.matches = matches; listeners.forEach(listener => listener()); });
}

test('offers all three choices and automatically follows system changes', () => {
  render(<ThemeSelector />);
  const selector = screen.getByRole('combobox', { name: 'Darstellung' });
  expect(screen.getAllByRole('option').map(option => option.textContent)).toEqual(['Hell', 'Dunkel', 'Automatisch']);
  expect(selector).toHaveValue('system');
  expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  systemDark(true);
  expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  expect(selector).toHaveValue('system');
});

test('manual choices override the system and survive remounting', () => {
  const first = render(<ThemeSelector />);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'dark' } });
  expect(localStorage.getItem('theme')).toBe('dark');
  systemDark(false);
  expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  first.unmount();
  render(<ThemeSelector />);
  expect(screen.getByRole('combobox')).toHaveValue('dark');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'light' } });
  systemDark(true);
  expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'system' } });
  expect(localStorage.getItem('theme')).toBe('system');
  expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
});

test('an invalid saved preference uses automatic mode', () => {
  localStorage.setItem('theme', 'invalid');
  media.matches = true;
  render(<ThemeSelector />);
  expect(screen.getByRole('combobox')).toHaveValue('system');
  expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
});

test('blocked local storage still allows changing the current appearance', () => {
  jest.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('Storage disabled'); });
  jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Storage disabled'); });
  render(<ThemeSelector />);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'dark' } });
  expect(screen.getByRole('combobox')).toHaveValue('dark');
  expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
});

test('keeps mounted selectors and changes in other tabs synchronized', () => {
  const page = render(<><ThemeSelector /><ThemeSelector /></>);
  fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: 'dark' } });
  expect(screen.getAllByRole('combobox')[1]).toHaveValue('dark');
  localStorage.setItem('theme', 'light');
  act(() => window.dispatchEvent(new StorageEvent('storage', { key: 'theme', newValue: 'light' })));
  screen.getAllByRole('combobox').forEach(selector => expect(selector).toHaveValue('light'));
  expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  page.unmount();
  expect(listeners.size).toBe(0);
});
