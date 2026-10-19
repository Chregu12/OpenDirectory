import { api } from './api';

export interface DirectoryUser {
  id: string;
  username: string;
  email: string;
  displayName?: string;
  department?: string;
  title?: string;
  enabled: boolean;
  revision: string;
  createdAt: string;
  updatedAt?: string;
}

export interface DirectoryAccess {
  subject: string;
  userId: string | null;
  permissions: string[];
  demoMode: boolean;
  directoryReadProtocol?: number;
  directoryCreationProtocol?: number;
  directoryUserMutationProtocol?: number;
  directoryGroupMutationProtocol?: number;
  directoryOuMutationProtocol?: number;
  directoryOuMembershipProtocol?: number;
  groupMembershipReviewProtocol?: number;
  organizationProfileProtocol?: number;
  organizationDelegationProtocol?: number;
  companyRegistrationReviewProtocol?: number;
  companyOwner?: boolean;
}

export type UserProfile = Pick<DirectoryUser, 'username' | 'email' | 'displayName' | 'department' | 'title'>;
export interface UserPage { users: DirectoryUser[]; total: number; page: number; limit: number }

function id(value: string) {
  if (typeof value !== 'string' || value.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) throw new Error('Ungültige Verzeichnis-ID.');
  return value;
}

export function userEtag(user: DirectoryUser) { return `"user-${id(user.id)}-${user.revision}"`; }
export function userName(user: DirectoryUser) { return user.displayName || user.username; }

export function parseUser(value: any): DirectoryUser {
  id(value?.id);
  if (typeof value.username !== 'string' || !value.username || typeof value.email !== 'string' || !value.email || typeof value.enabled !== 'boolean'
    || typeof value.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.revision) || /\s/.test(value.revision)
    || (value.revision.length === 19 && value.revision > '9223372036854775807')
    || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt))
    || ['displayName', 'department', 'title', 'updatedAt'].some(field => value[field] !== undefined && typeof value[field] !== 'string')) throw new Error('Ungültige Verzeichnisantwort. Ergebnis nicht bestätigt; bitte neu laden.');
  return { id: value.id, username: value.username, email: value.email, displayName: value.displayName, department: value.department,
    title: value.title, enabled: value.enabled, revision: value.revision, createdAt: value.createdAt, updatedAt: value.updatedAt };
}

export function directoryError(error: any) {
  if (error?.response?.status === 409 && error?.response?.data?.error === 'user_has_organization_memberships') return 'Der Benutzer besitzt noch OU-Zuordnungen. Entferne diese ausdrücklich vor der Löschung.';
  if (error?.response?.status === 412) return 'Der Datensatz wurde zwischenzeitlich geändert. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.';
  if (error?.response?.status === 403) return 'Keine Berechtigung für diese Verzeichnisaktion.';
  if (error?.response?.status === 401) return 'Die Sitzung ist nicht mehr gültig. Bitte erneut anmelden.';
  if (error?.response?.status === 404) return 'Der Verzeichniseintrag existiert nicht mehr.';
  if (error?.response?.status === 400) return 'Die Eingaben wurden abgelehnt. Bitte prüfen.';
  return 'Verzeichnisantwort nicht bestätigt. Bitte neu laden, bevor du die Aktion erneut ausführst.';
}

export async function requireDirectoryRead() {
  const access = await directoryUsers.access();
  if (access.directoryReadProtocol !== 1 || access.userId === null) throw new Error('Mandantengebundene Verzeichniszugriffe nicht bestätigt.');
}

async function requireUserMutation() {
  const access = await directoryUsers.access();
  if (access.directoryUserMutationProtocol !== 1 || access.userId === null || access.demoMode) throw new Error('Mandantengebundene Benutzeränderung nicht bestätigt.');
}

export const directoryUsers = {
  async access(): Promise<DirectoryAccess> {
    const { data } = await api.get('/api/identity/access');
    if (typeof data?.subject !== 'string' || !data.subject || !Array.isArray(data.permissions) || data.permissions.some((value: unknown) => typeof value !== 'string')
      || typeof data.demoMode !== 'boolean' || (data.userId !== null && typeof data.userId !== 'string')) throw new Error('Berechtigungen nicht bestätigt.');
    if (data.userId !== null) id(data.userId);
    return data;
  },
  async list(page = 1, search = '', enabled = '', signal?: AbortSignal): Promise<UserPage> {
    await requireDirectoryRead();
    const { data } = await api.get('/api/users', { params: { page, limit: 25, ...(search ? { search } : {}), ...(enabled ? { enabled } : {}) }, signal });
    if (!Array.isArray(data?.users) || !Number.isSafeInteger(data.total) || data.total < 0 || data.page !== page || data.limit !== 25
      || data.users.length > 25 || data.users.length > data.total) throw new Error('Benutzerliste nicht bestätigt.');
    return { ...data, users: data.users.map(parseUser) };
  },
  async get(userId: string, signal?: AbortSignal): Promise<DirectoryUser> {
    const target = id(userId); await requireDirectoryRead();
    const user = parseUser((await api.get('/api/users/' + target, { signal })).data);
    if (user.id !== userId) throw new Error('Benutzerantwort stimmt nicht überein.');
    return user;
  },
  async create(profile: UserProfile) {
    const access = await directoryUsers.access();
    if (access.directoryCreationProtocol !== 1 || access.userId === null) throw new Error('Mandantengebundene Verzeichniserstellung nicht bestätigt.');
    const user = parseUser((await api.post('/api/users', profile)).data);
    if (user.enabled) throw new Error('Sicherer Erstellstatus nicht bestätigt.');
    return user;
  },
  async update(user: DirectoryUser, patch: Partial<UserProfile> & { enabled?: boolean }) {
    const target = id(user.id); await requireUserMutation();
    const result = parseUser((await api.put('/api/users/' + target, patch, { headers: { 'If-Match': userEtag(user) } })).data);
    if (result.id !== user.id || result.revision === user.revision || (patch.enabled !== undefined && result.enabled !== patch.enabled)) throw new Error('Änderung nicht bestätigt. Bitte neu laden.');
    return result;
  },
  async remove(user: DirectoryUser) {
    const target = id(user.id); await requireUserMutation();
    const response = await api.delete('/api/users/' + target, { headers: { 'If-Match': userEtag(user) } });
    if (response.status !== 204) throw new Error('Löschung nicht bestätigt. Bitte neu laden.');
  },
  async invalidate(userId: string) {
    const target = id(userId); await requireUserMutation();
    const { data } = await api.post('/api/users/' + target + '/authorization/invalidate', {});
    if (data?.userId !== userId || typeof data.revision !== 'string' || !/^[1-9][0-9]*$/.test(data.revision) || /\s/.test(data.revision)) throw new Error('Sicherheitsreset nicht bestätigt.');
    return data;
  },
};
