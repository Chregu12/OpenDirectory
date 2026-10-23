import { api } from './api';

export type EmployeeInvitationRecord = {
  id: string; tenantId: string; userId: string; loginName: string; organizationName: string;
  status: 'pending' | 'credential_pending' | 'accepted' | 'revoked'; revision: string; createdAt: string; expiresAt: string;
  credentialCreated: boolean; identityConfirmed: boolean;
};
export type EmployeeInvitationTarget = { id: string; revision: string; username: string; email: string };

const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function validRecord(value: any): value is EmployeeInvitationRecord {
  return !!value && !Array.isArray(value) && Object.keys(value).length === 11 && uuid.test(value.id) && uuid.test(value.tenantId) && uuid.test(value.userId)
    && typeof value.loginName === 'string' && typeof value.organizationName === 'string' && ['pending', 'credential_pending', 'accepted', 'revoked'].includes(value.status)
    && typeof value.revision === 'string' && /^[1-9][0-9]{0,18}$/.test(value.revision)
    && ['createdAt', 'expiresAt'].every(field => typeof value[field] === 'string' && Number.isFinite(Date.parse(value[field])))
    && typeof value.credentialCreated === 'boolean' && typeof value.identityConfirmed === 'boolean' && value.identityConfirmed === (value.status === 'accepted');
}
function ownerPost<T>(operation: string, body: object) {
  return api.post<T>('/api/employee-invitations/manage/' + operation, body, { headers: { 'X-OD-Employee-Invitation-Owner': '1' } });
}

export function employeeInvitationManagementError(error: any) {
  const status = error?.response?.status;
  if (status === 401) return 'Sitzung abgelaufen. Bitte erneut anmelden.';
  if (status === 403 || status === 428) return 'Nur der aktuelle Firmeninhaber mit frischer MFA kann Einladungen verwalten.';
  if (status === 404) return 'Der Eintrag wurde nicht gefunden. Bitte neu laden.';
  if (status === 409 || status === 412) return 'Einladung oder Benutzer wurde inzwischen geändert. Bitte Liste aktualisieren und erneut prüfen.';
  if (status === 429) return 'Zu viele Einladungsaktionen. Bitte später erneut versuchen.';
  return 'Einladungsdienst nicht verfügbar. Prüfe den aktuellen Stand, bevor du eine Aktion wiederholst.';
}

export const employeeInvitationManagement = {
  async target(userId: string, expectedOwnerId: string): Promise<EmployeeInvitationTarget> {
    if (!uuid.test(userId)) throw new Error('Ungültiger Verzeichnisbenutzer.');
    const { data } = await api.post('/api/identity/employee-invitations', { userId });
    const target = data?.target;
    if (data?.schemaVersion !== 1 || data?.employeeInvitationProtocol !== 1 || data?.actorUserId !== expectedOwnerId
      || !uuid.test(data?.tenant?.id || '') || !target || Object.keys(target).length !== 8 || target.id !== userId
      || typeof target.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(target.revision)
      || typeof target.username !== 'string' || typeof target.email !== 'string' || target.enabled !== false || target.unlinked !== true || target.ordinary !== true) {
      throw new Error('Der ausgewählte Benutzer ist nicht als gewöhnliches, deaktiviertes und unverknüpftes Einladungsziel bestätigt.');
    }
    return { id: target.id, revision: target.revision, username: target.username, email: target.email };
  },
  async list(page = 1) {
    const { data } = await ownerPost<any>('list', { page });
    if (data?.schemaVersion !== 1 || data?.employeeInvitationProtocol !== 1 || data.page !== page || typeof data.hasMore !== 'boolean'
      || !Array.isArray(data.invitations) || data.invitations.length > 25 || data.invitations.some((value: any) => !validRecord(value))) throw new Error('Einladungsliste nicht bestätigt.');
    return data as { schemaVersion: 1; employeeInvitationProtocol: 1; page: number; hasMore: boolean; invitations: EmployeeInvitationRecord[] };
  },
  async create(input: { id: string; userId: string; userRevision: string; loginName: string; durationHours: number; reason: string; confirm: true }) {
    const { data } = await ownerPost<any>('create', input);
    if (data?.schemaVersion !== 1 || data?.employeeInvitationProtocol !== 1 || !validRecord(data.invitation) || typeof data.created !== 'boolean'
      || (data.created ? typeof data.invitationToken !== 'string' || !/^[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/.test(data.invitationToken) : data.invitationToken !== null)) throw new Error('Einladungsergebnis nicht bestätigt.');
    return data as { schemaVersion: 1; employeeInvitationProtocol: 1; invitation: EmployeeInvitationRecord; created: boolean; invitationToken: string | null };
  },
  async revoke(input: { id: string; revision: string; reason: string; confirm: true }) {
    const { data } = await ownerPost<any>('revoke', input);
    if (data?.schemaVersion !== 1 || data?.employeeInvitationProtocol !== 1 || !validRecord(data.invitation) || data.invitation.id !== input.id
      || data.invitation.status !== 'revoked' || data.partialEnrollmentWithdrawn !== true) throw new Error('Widerrufsergebnis nicht bestätigt.');
    return data as { schemaVersion: 1; employeeInvitationProtocol: 1; invitation: EmployeeInvitationRecord; partialEnrollmentWithdrawn: true };
  },
};
