'use client';

import { useTheme, type Theme } from '@/hooks/useTheme';

export default function ThemeSelector() {
  const { theme, setTheme } = useTheme();
  return (
    <select
      aria-label="Darstellung"
      title="Darstellung: Hell, Dunkel oder automatisch nach Systemeinstellung"
      value={theme}
      onChange={event => setTheme(event.target.value as Theme)}
      style={{ backgroundColor: 'var(--bg-input)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)',
        borderRadius: 8, padding: '6px 24px 6px 8px', fontSize: 12, cursor: 'pointer', maxWidth: 'clamp(88px, 30vw, 125px)' }}
    >
      <option value="light">Hell</option>
      <option value="dark">Dunkel</option>
      <option value="system">Automatisch</option>
    </select>
  );
}
