import { api } from './api';
import { MfaCredentials, MfaSetup } from './verifiedMfa';

export interface RecoverySetup extends MfaSetup { challenge: string }
function object(value: any, fields: string[]) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function remaining(data: any): number {
  if (!object(data, ['remaining']) || !Number.isInteger(data.remaining) || data.remaining < 0 || data.remaining > 8) throw new Error('Notfallcode-Status nicht bestätigt.');
  return data.remaining;
}
function setup(data: any): RecoverySetup {
  if (!object(data, ['challenge', 'secret', 'otpauthUri', 'expiresAt']) || typeof data.challenge !== 'string'
    || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\.[A-Za-z0-9_-]{43}$/.test(data.challenge)
    || typeof data.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(data.secret) || typeof data.otpauthUri !== 'string'
    || !/^otpauth:\/\/totp\/OpenDirectory:[a-f0-9-]{36}\?secret=[A-Z2-7]{32}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30$/.test(data.otpauthUri)
    || !data.otpauthUri.includes('secret=' + data.secret + '&') || typeof data.expiresAt !== 'string' || !Number.isFinite(Date.parse(data.expiresAt))) throw new Error('Wiederherstellung nicht bestätigt. Nicht automatisch wiederholen.');
  return data;
}
async function publicRequest(action: 'start' | 'confirm', body: object, purpose: 'recovery' | 'enrollment' = 'recovery'): Promise<any> {
  const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('/api/auth/oidc/' + purpose + '/' + action, { method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json', [purpose === 'enrollment' ? 'X-OD-Enrollment' : 'X-OD-Recovery']: '1' }, body: JSON.stringify(body), signal: controller.signal });
    if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('Unbestätigtes Ergebnis. Nicht automatisch wiederholen.');
    const data = await response.json();
    if (!response.ok) throw Object.assign(new Error('Wiederherstellung abgelehnt.'), { response: { status: response.status, data } });
    if (response.status !== 200) throw new Error('Unbestätigtes Ergebnis. Nicht automatisch wiederholen.');
    return data;
  } finally { clearTimeout(timeout); }
}

export const mfaRecovery = {
  async status(signal?: AbortSignal) { return remaining((await api.get('/api/mfa/recovery-codes', { signal })).data); },
  async rotate(credentials: MfaCredentials, code: string): Promise<string[]> {
    const { data } = await api.post('/api/mfa/recovery-codes', { ...credentials, code });
    if (!object(data, ['remaining', 'recoveryCodes']) || data.remaining !== 8 || !Array.isArray(data.recoveryCodes) || data.recoveryCodes.length !== 8
      || new Set(data.recoveryCodes).size !== 8 || data.recoveryCodes.some((value: any) => typeof value !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{8}){3}$/.test(value))) throw new Error('Neue Codes nicht bestätigt. Nicht automatisch wiederholen; erneut anmelden und neue Codes ausdrücklich anfordern.');
    return data.recoveryCodes;
  },
  async start(credentials: MfaCredentials, recoveryCode: string): Promise<RecoverySetup> { return setup(await publicRequest('start', { ...credentials, recoveryCode })); },
  async confirm(challenge: string, code: string) {
    const data = await publicRequest('confirm', { challenge, code });
    if (!object(data, ['enabled', 'reauthenticationRequired']) || data.enabled !== true || data.reauthenticationRequired !== true) throw new Error('Faktorwechsel nicht bestätigt. Nicht automatisch wiederholen; normale Anmeldung mit dem neuen Faktor prüfen.');
  },
};
export const mfaEnrollment = {
  async start(clientId: string, credentials: MfaCredentials): Promise<RecoverySetup> { return setup(await publicRequest('start', { clientId, ...credentials }, 'enrollment')); },
  async confirm(challenge: string, code: string) {
    const data = await publicRequest('confirm', { challenge, code }, 'enrollment');
    if (!object(data, ['enabled', 'reauthenticationRequired']) || data.enabled !== true || data.reauthenticationRequired !== true) throw new Error('Ersteinrichtung nicht bestätigt. Nicht automatisch wiederholen; normale Anmeldung prüfen.');
  },
};

export function recoveryError(error: any, enrollment = false): string {
  const errors: Record<string, string> = {
    invalid_recovery_code_format: 'Notfallcode im angezeigten Format mit Kleinbuchstaben eingeben.',
    invalid_recovery_code: 'Notfallcode nicht gültig, bereits verbraucht oder ersetzt.',
    invalid_recovery_challenge: 'Wiederherstellung abgelaufen, ersetzt oder bereits abgeschlossen.',
    invalid_credentials: 'Anmeldedaten nicht bestätigt.', mfa_required: 'Der Passwortanbieter verlangt zusätzlich seinen eigenen MFA-Code.',
    invalid_otp: 'Code des neuen Authenticators nicht bestätigt. Einen neuen Code eingeben.',
    mfa_temporarily_locked: 'Zu viele Fehlversuche. Fünf Minuten warten.',
    recovery_identity_changed: 'Die Verzeichnisberechtigung hat sich geändert. Wiederherstellung nicht erlaubt.',
    browser_auth_origin_or_csrf_denied: 'Anfrage nicht vom erlaubten Portal.',
    mfa_enrollment_not_allowed: 'Keine verbindliche Anwendungs- oder Rollenrichtlinie für diese Ersteinrichtung. Richtlinie und Anwendungs-ID prüfen.',
    mfa_already_enabled: 'Ein Faktor ist bereits eingerichtet. Normal anmelden oder die Notfallcode-Wiederherstellung verwenden.',
    invalid_enrollment_challenge: 'Ersteinrichtung abgelaufen, ersetzt oder bereits abgeschlossen.',
    enrollment_authorization_changed: 'Benutzer, Anwendungszugriff oder Richtlinie hat sich geändert. Einrichtung nicht erlaubt.',
    application_not_assigned: 'Für diese Anwendung besteht keine gültige Benutzer- oder Gruppenzuweisung.',
  };
  return errors[error?.response?.data?.error] || (enrollment ? 'Ersteinrichtung nicht bestätigt. Nicht automatisch wiederholen; nach einem unklaren Abschluss zuerst die normale Anmeldung mit dem neuen Authenticator prüfen.' : 'Ergebnis unbekannt. Nicht automatisch wiederholen. Bei verlorenem Start-Ergebnis einen anderen Notfallcode verwenden; nach unklarem Abschluss die normale Anmeldung mit dem neuen Authenticator prüfen.');
}
