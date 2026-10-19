'use client';

import { useEffect, useState } from 'react';
import { qaGet } from '@/lib/quickActionsApi';

interface QuickActionAccess {
  subject: string;
  permissions: string[];
  onboardingDepartments?: string[];
  delegablePermissions?: string[] | null;
}

export function useQuickActionAccess() {
  const [access, setAccess] = useState<QuickActionAccess | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let active = true;
    qaGet<QuickActionAccess>('/api/quick/access').then(result => {
      if (typeof result?.subject !== 'string' || !result.subject.trim() || !Array.isArray(result.permissions) || result.permissions.some(permission => typeof permission !== 'string')) throw new Error('Invalid permissions');
      if (result.onboardingDepartments !== undefined && (!Array.isArray(result.onboardingDepartments) || result.onboardingDepartments.some(department => typeof department !== 'string'))) throw new Error('Invalid departments');
      if (result.delegablePermissions != null && (!Array.isArray(result.delegablePermissions) || result.delegablePermissions.some(permission => typeof permission !== 'string'))) throw new Error('Invalid delegation');
      if (active) setAccess(result);
    }).catch(() => { if (active) setUnavailable(true); });
    return () => { active = false; };
  }, []);
  return { access, unavailable, can: (permission: string) => access?.permissions.includes(permission) === true };
}
