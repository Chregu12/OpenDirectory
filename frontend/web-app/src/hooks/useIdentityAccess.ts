'use client';

import { useEffect, useState, useCallback } from 'react';
import { directoryUsers, DirectoryAccess } from '@/lib/directoryUsers';

export function useIdentityAccess() {
  const [access, setAccess] = useState<DirectoryAccess | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => { setAccess(null); setUnavailable(false); setAttempt(value => value + 1); }, []);
  useEffect(() => {
    let active = true;
    directoryUsers.access().then(result => { if (active) setAccess(result); }).catch(() => { if (active) { setAccess(null); setUnavailable(true); } });
    return () => { active = false; };
  }, [attempt]);
  return { access, unavailable, reload, can: (permission: string) => access?.permissions.includes(permission) === true };
}
