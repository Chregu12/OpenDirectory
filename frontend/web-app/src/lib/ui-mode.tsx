'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

type UiMode = 'simple' | 'expert';

interface UiModeContextType {
  mode: UiMode;
  isSimple: boolean;
  isExpert: boolean;
  toggleMode: () => void;
  setMode: (mode: UiMode) => void;
}

const UiModeContext = createContext<UiModeContextType>({
  mode: 'simple',
  isSimple: true,
  isExpert: false,
  toggleMode: () => {},
  setMode: () => {},
});

const STORAGE_KEY = 'od_ui_mode';

export function UiModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<UiMode>('simple');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'expert' || stored === 'simple') {
        setModeState(stored);
      }
    }
  }, []);

  const setMode = useCallback((newMode: UiMode) => {
    setModeState(newMode);
    if (typeof window !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, newMode);
    }
  }, []);

  const toggleMode = useCallback(() => {
    setMode(mode === 'simple' ? 'expert' : 'simple');
  }, [mode, setMode]);

  return (
    <UiModeContext.Provider
      value={{
        mode,
        isSimple: mode === 'simple',
        isExpert: mode === 'expert',
        toggleMode,
        setMode,
      }}
    >
      {children}
    </UiModeContext.Provider>
  );
}

export function useUiMode() {
  return useContext(UiModeContext);
}
