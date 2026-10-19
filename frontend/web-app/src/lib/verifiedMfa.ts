import { api } from './api';

export interface MfaStatus { enabled: boolean; pending: boolean; pendingOwned: boolean; method: 'totp'; reauthenticationRequiredAfterChange: true }
export interface MfaSetup { secret: string; otpauthUri: string; expiresAt: string }
export interface MfaCredentials { username: string; password: string; mfaCode?: string }

function object(value: any, fields: string[]) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

export const verifiedMfa = {
  async status(signal?: AbortSignal): Promise<MfaStatus> {
    const { data } = await api.get('/api/mfa', { signal });
    if (!object(data, ['enabled', 'pending', 'pendingOwned', 'method', 'reauthenticationRequiredAfterChange'])
      || typeof data.enabled !== 'boolean' || typeof data.pending !== 'boolean' || typeof data.pendingOwned !== 'boolean'
      || data.method !== 'totp' || data.reauthenticationRequiredAfterChange !== true || (data.enabled && data.pending) || (data.pendingOwned && !data.pending)) throw new Error('MFA-Status nicht bestätigt.');
    return data;
  },
  async enroll(credentials: MfaCredentials): Promise<MfaSetup> {
    const { data } = await api.post('/api/mfa/enroll', credentials);
    if (!object(data, ['secret', 'otpauthUri', 'expiresAt']) || typeof data.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(data.secret)
      || typeof data.otpauthUri !== 'string' || !/^otpauth:\/\/totp\/OpenDirectory:[a-f0-9-]{36}\?secret=[A-Z2-7]{32}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30$/.test(data.otpauthUri)
      || !data.otpauthUri.includes('secret=' + data.secret + '&') || typeof data.expiresAt !== 'string' || !Number.isFinite(Date.parse(data.expiresAt))) throw new Error('Einrichtung nicht bestätigt. Keine automatische Wiederholung; Status prüfen.');
    return data;
  },
  async confirm(code: string) {
    const { data } = await api.post('/api/mfa/confirm', { code });
    if (!object(data, ['enabled', 'reauthenticationRequired']) || data.enabled !== true || data.reauthenticationRequired !== true) throw new Error('Aktivierung nicht bestätigt. Erneut anmelden und Status prüfen.');
    return data;
  },
  async disable(credentials: MfaCredentials, code: string) {
    const { data } = await api.post('/api/mfa/disable', { ...credentials, code });
    if (!object(data, ['enabled', 'reauthenticationRequired']) || data.enabled !== false || data.reauthenticationRequired !== true) throw new Error('Deaktivierung nicht bestätigt. Erneut anmelden und Status prüfen.');
    return data;
  },
};

export function mfaError(error: any): string {
  const messages: Record<string, string> = {
    invalid_otp: 'Code ungültig oder bereits verwendet. Einen neuen Code abwarten.',
    mfa_temporarily_locked: 'Zu viele Fehlversuche. Fünf Minuten warten.',
    mfa_setup_not_pending: 'Einrichtung abgelaufen oder an eine andere Sitzung gebunden. Status prüfen.',
    same_user_required: 'Nur die Anmeldedaten des eigenen Kontos sind erlaubt.',
    invalid_credentials: 'Anmeldedaten nicht bestätigt.',
    mfa_required: 'Der Passwortanbieter verlangt seinen eigenen MFA-Code.',
    mfa_already_enabled: 'MFA ist bereits aktiviert. Status neu laden.',
  };
  return messages[error?.response?.data?.error] || error?.message || 'Ergebnis unbekannt. Nicht automatisch wiederholen; erneut anmelden und Status prüfen.';
}
