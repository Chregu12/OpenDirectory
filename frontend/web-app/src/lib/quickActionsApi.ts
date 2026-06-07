/**
 * Quick-Actions API client — talks directly to the quick-actions service at
 * NEXT_PUBLIC_QUICK_ACTIONS_URL (defaults to http://localhost:3950).
 *
 * Unlike the main `api` client this does NOT go through the Next.js rewrite
 * proxy; the quick-actions service is a standalone Express app.
 */

const BASE =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_QUICK_ACTIONS_URL) ||
  'http://localhost:3950';

// ─── Result interfaces ────────────────────────────────────────────────────────

export interface CreateSPResult {
  clientId: string;
  clientSecret: string;
  spn: string;
  appName?: string;
  serviceAccountDn?: string;
  permissions?: string[];
  success?: boolean;
  completedSteps?: string[];
  warnings?: string[];
}

export interface EnrollDeviceResult {
  deviceId: string;
  computerDn?: string;
  enrollmentUrl?: string;
  platformConfig?: Record<string, unknown>;
  nextSteps?: string[];
}

export interface OnboardUserResult {
  userId: string;
  userDn?: string;
  temporaryPassword: string;
  username?: string;
  assignedDevice?: Record<string, unknown> | null;
  groupMemberships?: string[];
}

export interface RotateSecretResult {
  clientId: string;
  newClientSecret: string;
  rotatedAt?: string;
}

// ─── Core helpers ─────────────────────────────────────────────────────────────

export async function qaPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`);
  }
  return data as T;
}

export async function qaGet<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`);
  }
  return data as T;
}

export async function qaDelete<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: 'DELETE' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`);
  }
  return data as T;
}
