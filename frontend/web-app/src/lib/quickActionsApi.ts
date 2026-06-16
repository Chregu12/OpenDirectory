/**
 * Quick-Actions API client — talks directly to the quick-actions service at
 * NEXT_PUBLIC_QUICK_ACTIONS_URL (defaults to http://localhost:3950).
 *
 * Unlike the main `api` client this does NOT go through the Next.js rewrite
 * proxy; the quick-actions service is a standalone Express app.
 */

import { getAccessToken, refreshTokens, setTokens, startLogin } from './auth';

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

// ─── Auth helpers ─────────────────────────────────────────────────────────────

function buildHeaders(): Record<string, string> {
  const token = getAccessToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

async function handleUnauthorized(): Promise<boolean> {
  const storedRefreshToken = localStorage.getItem('refresh_token');
  if (!storedRefreshToken) return false;
  try {
    const tokens = await refreshTokens(storedRefreshToken);
    setTokens(tokens);
    return true;
  } catch {
    return false;
  }
}

// ─── Core helpers ─────────────────────────────────────────────────────────────

export async function qaPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  const url = `${BASE}${path}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders(),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (response.status === 401) {
    const refreshed = await handleUnauthorized();
    if (refreshed) {
      const retry = await fetch(url, {
        method: 'POST',
        headers: buildHeaders(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      if (retry.status === 401) {
        startLogin();
        return Promise.reject(new Error('Unauthorized'));
      }
      if (!retry.ok) throw new Error(`Request failed: ${retry.status}`);
      return retry.json() as Promise<T>;
    }
    startLogin();
    return Promise.reject(new Error('Unauthorized'));
  }

  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

export async function qaGet<T = unknown>(path: string): Promise<T> {
  const url = `${BASE}${path}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders(),
  });

  if (response.status === 401) {
    const refreshed = await handleUnauthorized();
    if (refreshed) {
      const retry = await fetch(url, {
        method: 'GET',
        headers: buildHeaders(),
      });
      if (retry.status === 401) {
        startLogin();
        return Promise.reject(new Error('Unauthorized'));
      }
      if (!retry.ok) throw new Error(`Request failed: ${retry.status}`);
      return retry.json() as Promise<T>;
    }
    startLogin();
    return Promise.reject(new Error('Unauthorized'));
  }

  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

export async function qaDelete<T = unknown>(path: string): Promise<T> {
  const url = `${BASE}${path}`;
  const response = await fetch(url, {
    method: 'DELETE',
    headers: buildHeaders(),
  });

  if (response.status === 401) {
    const refreshed = await handleUnauthorized();
    if (refreshed) {
      const retry = await fetch(url, {
        method: 'DELETE',
        headers: buildHeaders(),
      });
      if (retry.status === 401) {
        startLogin();
        return Promise.reject(new Error('Unauthorized'));
      }
      if (!retry.ok) throw new Error(`Request failed: ${retry.status}`);
      return retry.json() as Promise<T>;
    }
    startLogin();
    return Promise.reject(new Error('Unauthorized'));
  }

  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json() as Promise<T>;
}
