import { api } from './api';
import { directoryUsers, directoryError } from './directoryUsers';

export interface DirectoryOu { id: string; name: string; description?: string; parentId?: string; createdAt: string; updatedAt?: string; revision?: string; memberCount?: number }
export interface OuProfile { name: string; description: string | null; parentId: string | null }

function identifier(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
}
function revision(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && !/\s/.test(value) && (value.length < 19 || value <= '9223372036854775807');
}
export function ouEtag(unit: DirectoryOu) {
  if (!identifier(unit.id) || !revision(unit.revision)) throw new Error('OU-Version nicht bestätigt.'); return `"ou-${unit.id}-${unit.revision}"`;
}
export function ouError(error: any) {
  return error?.response?.status === 409 ? 'Die Änderung wurde abgelehnt: Abhängigkeiten, eine zyklische oder zu tiefe Hierarchie verhindern die Aktion. Bitte neu laden und prüfen.' : directoryError(error);
}
export function parseOu(value: any): DirectoryOu {
  if (!identifier(value?.id) || typeof value.name !== 'string' || !value.name.trim() || value.name.length > 255
    || value.description !== undefined && (typeof value.description !== 'string' || value.description.length > 2000)
    || value.parentId !== undefined && !identifier(value.parentId)
    || value.revision !== undefined && !revision(value.revision)
    || value.memberCount !== undefined && (!Number.isSafeInteger(value.memberCount) || value.memberCount < 0 || value.memberCount > 10000)
    || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt))
    || value.updatedAt !== undefined && (typeof value.updatedAt !== 'string' || !Number.isFinite(Date.parse(value.updatedAt)))) throw new Error('Organisationsstruktur nicht bestätigt.');
  return { id: value.id, name: value.name, description: value.description, parentId: value.parentId, createdAt: value.createdAt, updatedAt: value.updatedAt, revision: value.revision, memberCount: value.memberCount };
}
export function parseOus(value: any): DirectoryOu[] {
  if (!Array.isArray(value?.ous) || value.ous.length > 10000 || value.total !== value.ous.length) throw new Error('Vollständige Organisationsstruktur nicht bestätigt.');
  const ous = value.ous.map(parseOu); const nodes = new Map<string, DirectoryOu>(ous.map((unit: DirectoryOu) => [unit.id, unit]));
  if (nodes.size !== ous.length) throw new Error('Doppelte Organisationseinheit.');
  for (const unit of ous) {
    const seen = new Set<string>(); let current: DirectoryOu | undefined = unit;
    while (current) {
      if (seen.has(current.id) || seen.size >= 256) throw new Error('Ungültige Organisationshierarchie.');
      seen.add(current.id);
      if (current.parentId && !nodes.has(current.parentId)) throw new Error('Unvollständige Organisationshierarchie.');
      current = current.parentId ? nodes.get(current.parentId) : undefined;
    }
  }
  return ous;
}
async function requireProtocol(action: 'read' | 'create' | 'update' | 'delete' = 'read') {
  const access = await directoryUsers.access();
  if (access.demoMode || !access.userId || access.directoryReadProtocol !== 1 || !access.permissions.includes('ous.read')
    || action === 'create' && (access.directoryCreationProtocol !== 1 || !access.permissions.includes('ous.create'))
    || ['update', 'delete'].includes(action) && (access.directoryOuMutationProtocol !== 1 || !access.permissions.includes('ous.' + action))) throw new Error('Mandantengebundene Organisationsstruktur nicht verfügbar.');
}
export const directoryOus = {
  async list(signal?: AbortSignal) {
    await requireProtocol(); return parseOus((await api.get('/api/ous', { signal })).data);
  },
  async create(profile: OuProfile) {
    await requireProtocol('create'); const unit = parseOu((await api.post('/api/ous', profile)).data);
    if (unit.name !== profile.name.trim() || (unit.description || null) !== (profile.description?.trim() || null)
      || (unit.parentId || null) !== profile.parentId) throw new Error('Angefragte Organisationseinheit nicht bestätigt.');
    return unit;
  },
  async update(unit: DirectoryOu, patch: Partial<OuProfile>) {
    const expected = ouEtag(unit); await requireProtocol('update'); const changed = parseOu((await api.put('/api/ous/' + unit.id, patch, { headers: { 'If-Match': expected } })).data);
    const values = { name: unit.name, description: unit.description || null, parentId: unit.parentId || null, ...patch };
    if (changed.id !== unit.id || !revision(changed.revision) || BigInt(changed.revision) <= BigInt(unit.revision!) || changed.createdAt !== unit.createdAt
      || changed.name !== values.name.trim() || (changed.description || null) !== (values.description?.trim() || null) || (changed.parentId || null) !== values.parentId) throw new Error('OU-Änderung nicht bestätigt.');
    return changed;
  },
  async remove(unit: DirectoryOu) {
    const expected = ouEtag(unit); await requireProtocol('delete'); if ((await api.delete('/api/ous/' + unit.id, { headers: { 'If-Match': expected } })).status !== 204) throw new Error('OU-Löschung nicht bestätigt.');
  },
};
