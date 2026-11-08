'use client';

import { useState, useEffect } from 'react';

export type Theme = 'light' | 'dark' | 'system';

function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem('theme');
    if (stored === 'light' || stored === 'dark') return stored;
  } catch {}
  return 'system';
}

export function useTheme() {
  const [theme, setSelectedTheme] = useState<Theme>('system');

  useEffect(() => {
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    let selected = getStoredTheme();
    const apply = (next: Theme) => {
      selected = next;
      setSelectedTheme(next);
      document.documentElement.setAttribute('data-theme', next === 'system' ? (system.matches ? 'dark' : 'light') : next);
    };
    const systemChanged = () => { if (selected === 'system') apply(selected); };
    const preferenceChanged = (event: Event) => apply((event as CustomEvent<Theme>).detail);
    const storageChanged = (event: StorageEvent) => { if (event.key === 'theme' || event.key === null) apply(getStoredTheme()); };
    apply(selected);
    system.addEventListener('change', systemChanged);
    window.addEventListener('od:theme-change', preferenceChanged);
    window.addEventListener('storage', storageChanged);
    return () => {
      system.removeEventListener('change', systemChanged);
      window.removeEventListener('od:theme-change', preferenceChanged);
      window.removeEventListener('storage', storageChanged);
    };
  }, []);

  const setTheme = (next: Theme) => {
    try { localStorage.setItem('theme', next); } catch {}
    window.dispatchEvent(new CustomEvent('od:theme-change', { detail: next }));
  };

  return { theme, setTheme };
}
