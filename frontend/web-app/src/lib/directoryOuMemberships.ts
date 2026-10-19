import { api } from './api';
import { DirectoryOu, parseOu, ouEtag } from './directoryOus';
import { DirectoryAccess, directoryUsers, directoryError } from './directoryUsers';

export interface OuMember { id: string; ouId: string; userId: string; createdAt: string; profile?: { username: string; email: string; displayName?: string } }
export interface OuMemberPage { schemaVersion: 1; actorUserId: string; unit: DirectoryOu; members: OuMember[]; total: number; page: number; limit: number; profileAccess: boolean }
export interface OuMemberCommand { unit: DirectoryOu; membership: OuMember; action: 'member-add' | 'member-remove' }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)) throw new Error('Kanonische Zuordnungs-ID nicht bestätigt.'); return value;
}
function member(value: any, ouId: string, profiles: boolean): OuMember {
  identifier(value?.id); identifier(value?.ouId); identifier(value?.userId);
  if (value.ouId !== ouId || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt)) || (!profiles && value.profile !== undefined)) throw new Error('OU-Zuordnung nicht bestätigt.');
  if (profiles && (!value.profile || typeof value.profile.username !== 'string' || !value.profile.username || typeof value.profile.email !== 'string' || !value.profile.email
    || value.profile.displayName !== undefined && typeof value.profile.displayName !== 'string')) throw new Error('Berechtigtes Benutzerprofil nicht bestätigt.');
  return { id: value.id, ouId, userId: value.userId, createdAt: value.createdAt, ...(profiles ? { profile: { username: value.profile.username, email: value.profile.email, displayName: value.profile.displayName } } : {}) };
}
async function access(write = false): Promise<DirectoryAccess> {
  const verified = await directoryUsers.access();
  if (verified.demoMode || !verified.userId || verified.directoryOuMembershipProtocol !== 1 || !verified.permissions.includes('ous.read') || write && !verified.permissions.includes('ous.members.manage')) throw new Error('Mandantengebundene OU-Zuordnungen nicht verfügbar.'); return verified;
}
export function ouMembershipError(error: any) {
  return error?.response?.status === 409 ? 'Diese Zuordnung besteht bereits oder verletzt eine Grenze. Bitte den aktuellen Bestand neu laden.' : directoryError(error);
}
function command(data: any, previous: DirectoryOu, userId: string, membershipId: string | null, action: OuMemberCommand['action']): OuMemberCommand {
  const unit = parseOu(data?.unit); const result = member(data?.membership, previous.id, false);
  if (data.action !== action || unit.id !== previous.id || !unit.revision || BigInt(unit.revision) !== BigInt(previous.revision!) + BigInt(1) || unit.createdAt !== previous.createdAt
    || unit.name !== previous.name || unit.description !== previous.description || unit.parentId !== previous.parentId || result.userId !== userId || membershipId && result.id !== membershipId
    || !Number.isSafeInteger(unit.memberCount) || unit.memberCount !== previous.memberCount! + (action === 'member-add' ? 1 : -1)) throw new Error('Zuordnungsänderung nicht bestätigt.');
  return { unit, membership: result, action };
}
export const directoryOuMemberships = {
  async list(ouId: string, page = 1, signal?: AbortSignal): Promise<OuMemberPage> {
    const target = identifier(ouId); if (!Number.isSafeInteger(page) || page < 1 || page > 1000000) throw new Error('Ungültige Seite.'); const verified = await access();
    const { data } = await api.get('/api/ous/' + target + '/members', { params: { page, limit: 25 }, signal }); const unit = parseOu(data?.unit);
    if (data.schemaVersion !== 1 || data.actorUserId !== verified.userId || unit.id !== target || !unit.revision || data.page !== page || data.limit !== 25
      || data.profileAccess !== verified.permissions.includes('users.read') || !Array.isArray(data.members) || !Number.isSafeInteger(data.total) || data.total < 0 || data.total > 10000 || unit.memberCount !== data.total
      || data.members.length !== Math.min(25, Math.max(0, data.total - (page - 1) * 25))) throw new Error('Vollständiger Zuordnungsbestand nicht bestätigt.');
    const members = data.members.map((value: unknown) => member(value, target, data.profileAccess));
    if (new Set(members.map((link: OuMember) => link.id)).size !== members.length || new Set(members.map((link: OuMember) => link.userId)).size !== members.length) throw new Error('Doppelte OU-Zuordnung.');
    return { schemaVersion: 1, actorUserId: verified.userId!, unit, members, total: data.total, page, limit: 25, profileAccess: data.profileAccess };
  },
  async add(unit: DirectoryOu, userId: string): Promise<OuMemberCommand> {
    if (!Number.isSafeInteger(unit.memberCount) || unit.memberCount! < 0 || unit.memberCount! >= 10000) throw new Error('Zuordnungsbestand nicht bestätigt.');
    const target = identifier(userId); const expected = ouEtag(unit); await access(true);
    return command((await api.post('/api/ous/' + unit.id + '/members', { userId: target }, { headers: { 'If-Match': expected } })).data, unit, target, null, 'member-add');
  },
  async remove(unit: DirectoryOu, link: OuMember): Promise<OuMemberCommand> {
    if (!Number.isSafeInteger(unit.memberCount) || unit.memberCount! < 1 || unit.memberCount! > 10000) throw new Error('Zuordnungsbestand nicht bestätigt.');
    identifier(link.id); identifier(link.userId); if (link.ouId !== unit.id) throw new Error('Fremde Zuordnung.'); const expected = ouEtag(unit); await access(true);
    return command((await api.delete('/api/ous/' + unit.id + '/members/' + link.id, { headers: { 'If-Match': expected } })).data, unit, link.userId, link.id, 'member-remove');
  },
};
