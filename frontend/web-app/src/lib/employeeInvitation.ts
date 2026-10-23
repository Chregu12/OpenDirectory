export type EmployeeInvitationPreview = {
  organizationName: string;
  loginName: string;
  status: 'pending' | 'credential_pending' | 'accepted';
  expiresAt: string;
  credentialCreated: boolean;
  identityConfirmed: boolean;
};

export type EmployeeInvitationAcceptance = {
  schemaVersion: 1;
  employeeInvitationProtocol: 1;
  status: 'accepted';
  organizationName: string;
  loginName: string;
  mfaEnrollmentRequired: true;
};

async function send<T>(path: string, body?: object, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: body ? { 'Content-Type': 'application/json', 'X-OD-Employee-Invitation': '1' } : {},
    ...(body ? { body: JSON.stringify(body) } : {}), signal: signal || AbortSignal.timeout(path.endsWith('/accept') ? 25000 : 10000) });
  if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw Object.assign(new Error('employee_invitation_unconfirmed'), { status: response.status });
  return response.json() as Promise<T>;
}

export function employeeInvitationError(error: any): string {
  if (error?.status === 400) return 'Das Einladungs-Token oder das Passwort entspricht nicht den Vorgaben.';
  if (error?.status === 401 || error?.status === 404) return 'Einladung oder Passwort ist ungültig. Prüfe den Link und versuche es erneut.';
  if (error?.status === 403) return 'Diese Einladung kann derzeit nicht eingelöst werden.';
  if (error?.status === 409) return 'Die Einladung oder der zugehörige Benutzer wurde inzwischen geändert. Bitte prüfe den Status erneut oder wende dich an deine IT.';
  if (error?.status === 429) return 'Zu viele Versuche. Bitte warte kurz und versuche es erneut.';
  return 'Der Abschluss wurde nicht bestätigt. Prüfe die Einladung erneut, bevor du den Vorgang wiederholst.';
}

export const employeeInvitation = {
  async capabilities(signal?: AbortSignal) {
    const value: any = await send('/api/employee-invitations', undefined, signal);
    if (!value || Object.keys(value).length !== 3 || value.schemaVersion !== 1 || typeof value.enabled !== 'boolean' || value.requiresFirstLoginMfa !== true) throw new Error('employee_invitation_unavailable');
    return value as { schemaVersion: 1; enabled: boolean; requiresFirstLoginMfa: true };
  },
  async inspect(token: string) {
    const value: any = await send('/api/employee-invitations/inspect', { token });
    if (!value || Object.keys(value).length !== 6 || typeof value.organizationName !== 'string' || typeof value.loginName !== 'string'
      || !['pending', 'credential_pending', 'accepted'].includes(value.status) || typeof value.expiresAt !== 'string'
      || typeof value.credentialCreated !== 'boolean' || typeof value.identityConfirmed !== 'boolean') throw new Error('employee_invitation_unavailable');
    return value as EmployeeInvitationPreview;
  },
  async accept(token: string, password: string) {
    const value: any = await send('/api/employee-invitations/accept', { token, password });
    if (!value || Object.keys(value).length !== 6 || value.schemaVersion !== 1 || value.employeeInvitationProtocol !== 1 || value.status !== 'accepted'
      || typeof value.organizationName !== 'string' || typeof value.loginName !== 'string' || value.mfaEnrollmentRequired !== true) throw new Error('employee_invitation_unavailable');
    return value as EmployeeInvitationAcceptance;
  },
};
