import { ensureSession, getAccessToken } from './auth';

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

async function qaRequest<Result>(method: string, path: string, body?: unknown): Promise<Result> {
  if (!path.startsWith('/api/quick/') || path.includes('\\')) throw new Error('Invalid quick-actions path');
  const token = getAccessToken() || (await ensureSession()).access_token;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch(path, {
      method, credentials: 'same-origin', redirect: 'error', signal: controller.signal,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) throw new Error(`Request failed: ${response.status}`);
    const data = await response.json();
    if (response.status === 207 || data?.success === false || (Number.isInteger(data?.failed) && data.failed > 0)) {
      const operation = response.headers?.get('x-od-operation-id');
      const reference = operation && /^[a-f0-9-]{36}$/i.test(operation) ? ` Vorgang: ${operation}.` : '';
      throw new Error('Vorgang nicht vollständig bestätigt. Teilobjekte können bereits bestehen; vor einem weiteren Versuch prüfen.' + reference);
    }
    return data as Result;
  } finally { clearTimeout(timer); }
}

export function qaPost<Result = unknown>(path: string, body?: unknown): Promise<Result> { return qaRequest('POST', path, body); }
export function qaGet<Result = unknown>(path: string): Promise<Result> { return qaRequest('GET', path); }
export function qaDelete<Result = unknown>(path: string): Promise<Result> { return qaRequest('DELETE', path); }
