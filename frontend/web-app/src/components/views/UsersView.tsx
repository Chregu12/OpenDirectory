'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  MagnifyingGlassIcon,
  PlusIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  XMarkIcon,
  UserCircleIcon,
  FolderIcon,
  FolderOpenIcon,
  TrashIcon,
  MinusCircleIcon,
  PencilIcon,
  UserGroupIcon,
  BuildingOfficeIcon,
} from '@heroicons/react/24/outline';
import { api, groupApi } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user' | 'read-only' | 'service-account';
  ou: string;
  status: 'aktiv' | 'inaktiv';
  lastActive: string;
  groups: string[];
  devices: string[];
  apps: string[];
  mfa: boolean;
}

interface ApiGroup {
  id: string;
  name: string;
  description?: string;
  ouId?: string | null;
  memberCount: number;
  createdAt?: string;
  members?: string[];
}

interface OUNode {
  id: string;
  name: string;
  description?: string;
  parentId?: string | null;
  children: OUNode[];
}

// Legacy local Group type for user wizard compatibility
interface Group {
  id: string;
  name: string;
  ou: string;
  memberCount: number;
  policies: string[];
}

// ─── Demo Data ────────────────────────────────────────────────────────────────

const DEMO_USERS: User[] = [
  { id: '1', name: 'Alice Müller', email: 'alice@firma.local', role: 'admin', ou: 'IT', status: 'aktiv', lastActive: 'vor 2 Stunden', groups: ['IT', 'Admins'], devices: ['MacBook Pro'], apps: ['Grafana', 'Nextcloud'], mfa: true },
  { id: '2', name: 'Bob Schneider', email: 'bob@firma.local', role: 'user', ou: 'Engineering', status: 'aktiv', lastActive: 'vor 1 Tag', groups: ['Engineering'], devices: ['Windows 11 Laptop'], apps: ['Nextcloud'], mfa: true },
  { id: '3', name: 'Carol Weber', email: 'carol@firma.local', role: 'user', ou: 'Marketing', status: 'aktiv', lastActive: 'vor 3 Tagen', groups: ['Marketing'], devices: [], apps: ['Nextcloud'], mfa: false },
  { id: '4', name: 'David Koch', email: 'david@firma.local', role: 'read-only', ou: 'Engineering', status: 'inaktiv', lastActive: 'vor 45 Tagen', groups: ['Engineering'], devices: [], apps: [], mfa: false },
  { id: '5', name: 'Eva Fischer', email: 'eva@firma.local', role: 'service-account', ou: 'IT', status: 'aktiv', lastActive: 'vor 5 Minuten', groups: ['IT'], devices: [], apps: ['Grafana'], mfa: false },
  { id: '6', name: 'Frank Meyer', email: 'frank@firma.local', role: 'user', ou: 'Marketing', status: 'aktiv', lastActive: 'vor 2 Tagen', groups: ['Marketing'], devices: ['Ubuntu Workstation'], apps: ['Nextcloud'], mfa: true },
];

const OU_OPTIONS = ['IT', 'Engineering', 'Marketing', 'Engineering/Backend', 'Engineering/Frontend'];

// ─── Role Badge ───────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: User['role'] }) {
  const map: Record<User['role'], string> = {
    admin: 'bg-red-100 text-red-800',
    user: 'bg-blue-100 text-blue-800',
    'read-only': 'bg-gray-100 text-gray-700',
    'service-account': 'bg-purple-100 text-purple-800',
  };
  const labels: Record<User['role'], string> = {
    admin: 'Admin',
    user: 'Benutzer',
    'read-only': 'Nur-Lesen',
    'service-account': 'Dienst-Konto',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${map[role]}`}>
      {labels[role]}
    </span>
  );
}

// ─── Status Dot ───────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: User['status'] }) {
  return (
    <span className="flex items-center gap-1.5 text-sm">
      <span className={`w-2 h-2 rounded-full ${status === 'aktiv' ? 'bg-green-500' : 'bg-gray-400'}`} />
      {status}
    </span>
  );
}

// ─── User Avatar ──────────────────────────────────────────────────────────────

function UserAvatar({ name }: { name: string }) {
  const initials = name.split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase();
  return (
    <div className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center text-white text-xs font-semibold flex-shrink-0">
      {initials}
    </div>
  );
}

// ─── OU Tree Node (sidebar) ───────────────────────────────────────────────────

function OUTreeNode({
  node,
  level,
  selectedOU,
  onSelect,
}: {
  node: OUNode;
  level: number;
  selectedOU: string | null;
  onSelect: (name: string | null) => void;
}) {
  const [open, setOpen] = useState(level === 0);
  const hasChildren = node.children.length > 0;
  const isSelected = selectedOU === node.name;

  return (
    <div>
      <button
        className={`w-full flex items-center gap-1 px-2 py-1.5 rounded text-sm text-left hover:bg-[#F2F2F7] ${isSelected ? 'bg-blue-50 text-[#0071E3] font-medium' : 'text-gray-700'}`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={() => {
          if (hasChildren) setOpen(o => !o);
          onSelect(isSelected ? null : node.name);
        }}
      >
        {hasChildren ? (
          open ? <ChevronDownIcon className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" /> : <ChevronRightIcon className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
        ) : (
          <span className="w-3.5 h-3.5 flex-shrink-0" />
        )}
        {open && hasChildren ? (
          <FolderOpenIcon className="w-4 h-4 text-yellow-500 flex-shrink-0" />
        ) : (
          <FolderIcon className="w-4 h-4 text-yellow-500 flex-shrink-0" />
        )}
        <span className="ml-1 truncate">{node.name}</span>
      </button>
      {open && hasChildren && (
        <div>
          {node.children.map(child => (
            <OUTreeNode key={child.id} node={child} level={level + 1} selectedOU={selectedOU} onSelect={onSelect} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Add User Wizard ──────────────────────────────────────────────────────────

function AddUserWizard({ onClose, onSuccess, availableGroups = [] }: { onClose: () => void; onSuccess: (u: User) => void; availableGroups?: ApiGroup[] }) {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    name: '', email: '', role: 'user' as User['role'],
    group: '', ou: 'IT',
    notify: true,
  });
  const [loading, setLoading] = useState(false);

  function set(k: string, v: string | boolean) {
    setForm(f => ({ ...f, [k]: v }));
  }

  async function submit() {
    setLoading(true);
    const username = form.email
      ? form.email.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '')
      : form.name.toLowerCase().replace(/\s+/g, '.').replace(/[^a-z0-9._-]/g, '');
    try {
      await api.post('/api/auth/register', {
        username,
        password: crypto.randomUUID().slice(0, 12) + 'A1!',
        name: form.name || username,
        email: form.email || `${username}@opendirectory.local`,
        role: form.role || 'user',
        groups: form.group ? [form.group] : [],
        ouId: form.ou,
      });
    } catch (_) {
      // API unavailable — proceed with optimistic local update
    }
    const newUser: User = {
      id: `new-${Date.now()}`,
      name: form.name,
      email: form.email,
      role: form.role,
      ou: form.ou,
      status: 'aktiv',
      lastActive: 'gerade eben',
      groups: form.group ? [form.group] : [],
      devices: [],
      apps: [],
      mfa: false,
    };
    onSuccess(newUser);
    setLoading(false);
    onClose();
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E5EA]">
          <h2 className="text-lg font-semibold text-gray-900">Nutzer hinzufügen</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-[#F2F2F7]">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <div className="flex items-center px-6 pt-4 gap-2">
          {[1, 2, 3].map(s => (
            <div key={s} className="flex items-center gap-2 flex-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0 ${step >= s ? 'bg-[#0071E3] text-white' : 'bg-gray-200 text-gray-500'}`}>
                {s}
              </div>
              {s < 3 && <div className={`flex-1 h-0.5 ${step > s ? 'bg-[#0071E3]' : 'bg-gray-200'}`} />}
            </div>
          ))}
        </div>

        <div className="px-6 py-4 space-y-4">
          {step === 1 && (
            <>
              <p className="text-sm font-medium text-gray-500">Schritt 1: Identität</p>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                <input className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]" value={form.name} onChange={e => set('name', e.target.value)} placeholder="Max Mustermann" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">E-Mail</label>
                <input type="email" className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]" value={form.email} onChange={e => set('email', e.target.value)} placeholder="max@firma.local" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rolle</label>
                <select className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]" value={form.role} onChange={e => set('role', e.target.value)}>
                  <option value="user">Benutzer</option>
                  <option value="admin">Admin</option>
                  <option value="read-only">Nur-Lesen</option>
                  <option value="service-account">Dienst-Konto</option>
                </select>
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <p className="text-sm font-medium text-gray-500">Schritt 2: Gruppe & OU</p>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Gruppe</label>
                <select className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]" value={form.group} onChange={e => set('group', e.target.value)}>
                  <option value="">Keine Gruppe</option>
                  {availableGroups.map(g => <option key={g.id} value={g.name}>{g.name}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Organisationseinheit (OU)</label>
                <select className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]" value={form.ou} onChange={e => set('ou', e.target.value)}>
                  {OU_OPTIONS.map(ou => <option key={ou} value={ou}>{ou}</option>)}
                </select>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <p className="text-sm font-medium text-gray-500">Schritt 3: Benachrichtigung</p>
              <div className="flex items-center gap-3 p-4 bg-gray-50 rounded-lg">
                <input type="checkbox" id="notify" checked={form.notify} onChange={e => set('notify', e.target.checked)} className="w-4 h-4 rounded text-[#0071E3]" />
                <label htmlFor="notify" className="text-sm text-gray-700">
                  Willkommens-E-Mail an <span className="font-medium">{form.email || 'den Benutzer'}</span> senden
                </label>
              </div>
              <div className="bg-blue-50 rounded-lg p-4 text-sm text-blue-800 space-y-1">
                <p className="font-medium">Zusammenfassung:</p>
                <p>Name: {form.name}</p>
                <p>E-Mail: {form.email}</p>
                <p>Rolle: {form.role}</p>
                <p>OU: {form.ou}</p>
                {form.group && <p>Gruppe: {form.group}</p>}
              </div>
            </>
          )}
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t border-[#E5E5EA]">
          <button onClick={step === 1 ? onClose : () => setStep(s => s - 1)} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">
            {step === 1 ? 'Abbrechen' : 'Zurück'}
          </button>
          {step < 3 ? (
            <button
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && (!form.name || !form.email)}
              className="px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Weiter
            </button>
          ) : (
            <button onClick={submit} disabled={loading} className="px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 disabled:opacity-50">
              {loading ? 'Speichern…' : 'Nutzer anlegen'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── User Detail Panel ────────────────────────────────────────────────────────

function UserDetailPanel({ user, onClose, onDeactivate, onDelete }: {
  user: User;
  onClose: () => void;
  onDeactivate: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-white shadow-2xl z-40 flex flex-col border-l border-[#E5E5EA]">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E5EA]">
        <div className="flex items-center gap-3">
          <UserAvatar name={user.name} />
          <div>
            <p className="font-semibold text-gray-900 text-sm">{user.name}</p>
            <p className="text-xs text-gray-500">{user.email}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-[#F2F2F7]">
          <XMarkIcon className="w-5 h-5 text-gray-500" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        <div className="flex items-center gap-3">
          <RoleBadge role={user.role} />
          <StatusDot status={user.status} />
        </div>

        <section>
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Gruppen</h3>
          {user.groups.length === 0 ? (
            <p className="text-sm text-gray-400">Keine Gruppen</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {user.groups.map(g => (
                <span key={g} className="inline-flex items-center gap-1 px-2.5 py-0.5 bg-gray-100 text-gray-700 text-xs rounded-full">
                  {g}
                  <button className="hover:text-red-500 ml-0.5">
                    <XMarkIcon className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </section>

        <section>
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Geräte</h3>
          {user.devices.length === 0 ? (
            <p className="text-sm text-gray-400">Keine Geräte</p>
          ) : (
            <ul className="space-y-1">
              {user.devices.map(d => (
                <li key={d} className="text-sm text-gray-700 bg-gray-50 px-3 py-1.5 rounded">{d}</li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className="text-sm font-semibold text-gray-700 mb-2">App-Zuweisungen</h3>
          {user.apps.length === 0 ? (
            <p className="text-sm text-gray-400">Keine Apps</p>
          ) : (
            <ul className="space-y-1">
              {user.apps.map(a => (
                <li key={a} className="text-sm text-gray-700 bg-gray-50 px-3 py-1.5 rounded">{a}</li>
              ))}
            </ul>
          )}
        </section>

        <section className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Zuletzt aktiv</span>
            <span className="text-gray-900">{user.lastActive}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">MFA</span>
            <span className={`font-medium ${user.mfa ? 'text-green-600' : 'text-red-600'}`}>
              {user.mfa ? 'Aktiv' : 'Inaktiv'}
            </span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">OU</span>
            <span className="text-gray-900">{user.ou}</span>
          </div>
        </section>
      </div>

      <div className="px-6 py-4 border-t border-[#E5E5EA] flex gap-3">
        <button
          onClick={() => onDeactivate(user.id)}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 border border-[#E5E5EA] text-gray-700 text-sm rounded-lg hover:bg-[#F2F2F7]"
        >
          <MinusCircleIcon className="w-4 h-4" />
          Deaktivieren
        </button>
        <button
          onClick={() => onDelete(user.id)}
          className="flex items-center justify-center gap-2 px-4 py-2 border border-red-200 text-red-600 text-sm rounded-lg hover:bg-red-50"
        >
          <TrashIcon className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ─── Group Form Modal ─────────────────────────────────────────────────────────

function GroupFormModal({
  onClose,
  onSuccess,
  initial,
}: {
  onClose: () => void;
  onSuccess: (g: ApiGroup) => void;
  initial?: ApiGroup;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function submit() {
    if (!name.trim()) return;
    setLoading(true);
    setError('');
    try {
      let res;
      if (initial) {
        res = await groupApi.updateGroup(initial.id, { name: name.trim(), description });
      } else {
        res = await groupApi.createGroup({ name: name.trim(), description });
      }
      onSuccess(res.data);
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.error ?? 'Fehler beim Speichern');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-sm">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E5EA]">
          <h2 className="text-lg font-semibold text-gray-900">{initial ? 'Gruppe bearbeiten' : 'Neue Gruppe'}</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-[#F2F2F7]">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name <span className="text-red-500">*</span></label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="z. B. Engineering"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Beschreibung</label>
            <textarea
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3] resize-none"
              rows={3}
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Optionale Beschreibung"
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#E5E5EA]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Abbrechen</button>
          <button
            onClick={submit}
            disabled={!name.trim() || loading}
            className="px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 disabled:opacity-50"
          >
            {loading ? 'Speichern…' : initial ? 'Speichern' : 'Erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Group Members Side Panel ─────────────────────────────────────────────────

function GroupMembersPanel({
  group,
  onClose,
  onGroupUpdated,
}: {
  group: ApiGroup;
  onClose: () => void;
  onGroupUpdated: (g: ApiGroup) => void;
}) {
  const [members, setMembers] = useState<string[]>(group.members ?? []);
  const [newMemberId, setNewMemberId] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');

  async function addMember() {
    const uid = newMemberId.trim();
    if (!uid) return;
    setAdding(true);
    setError('');
    try {
      await groupApi.addMember(group.id, uid);
      const updated = [...members, uid];
      setMembers(updated);
      setNewMemberId('');
      onGroupUpdated({ ...group, memberCount: updated.length, members: updated });
    } catch (e: any) {
      setError(e?.response?.data?.error ?? 'Fehler beim Hinzufügen');
    } finally {
      setAdding(false);
    }
  }

  async function removeMember(userId: string) {
    try {
      await groupApi.removeMember(group.id, userId);
      const updated = members.filter(m => m !== userId);
      setMembers(updated);
      onGroupUpdated({ ...group, memberCount: updated.length, members: updated });
    } catch {
      // optimistic — ignore
    }
  }

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-white shadow-2xl z-40 flex flex-col border-l border-[#E5E5EA]">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E5EA]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center">
            <UserGroupIcon className="w-4 h-4 text-[#0071E3]" />
          </div>
          <div>
            <p className="font-semibold text-gray-900 text-sm">{group.name}</p>
            <p className="text-xs text-gray-500">{members.length} Mitglieder</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-[#F2F2F7]">
          <XMarkIcon className="w-5 h-5 text-gray-500" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {/* Add member */}
        <div className="mb-5">
          <p className="text-sm font-semibold text-gray-700 mb-2">Mitglied hinzufügen</p>
          <div className="flex gap-2">
            <input
              className="flex-1 border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]"
              placeholder="Benutzer-ID oder Username"
              value={newMemberId}
              onChange={e => setNewMemberId(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addMember()}
            />
            <button
              onClick={addMember}
              disabled={!newMemberId.trim() || adding}
              className="px-3 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 disabled:opacity-50 flex-shrink-0"
            >
              <PlusIcon className="w-4 h-4" />
            </button>
          </div>
          {error && <p className="text-xs text-red-600 mt-1">{error}</p>}
        </div>

        {/* Member list */}
        <p className="text-sm font-semibold text-gray-700 mb-2">Mitglieder</p>
        {members.length === 0 ? (
          <div className="text-center py-8">
            <UserGroupIcon className="w-8 h-8 text-gray-300 mx-auto mb-2" />
            <p className="text-sm text-gray-400">Keine Mitglieder</p>
          </div>
        ) : (
          <ul className="space-y-2">
            {members.map(uid => (
              <li key={uid} className="flex items-center justify-between px-3 py-2 bg-[#F2F2F7] rounded-lg group">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full bg-indigo-500 flex items-center justify-center text-white text-xs font-semibold">
                    {uid.slice(0, 2).toUpperCase()}
                  </div>
                  <span className="text-sm text-gray-800">{uid}</span>
                </div>
                <button
                  onClick={() => removeMember(uid)}
                  className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-red-100 text-gray-400 hover:text-red-500 transition-all"
                >
                  <XMarkIcon className="w-4 h-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ─── Confirm Delete Dialog ────────────────────────────────────────────────────

function ConfirmDeleteDialog({
  title,
  message,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-sm">
        <div className="px-6 py-5">
          <h2 className="text-base font-semibold text-gray-900 mb-2">{title}</h2>
          <p className="text-sm text-gray-600">{message}</p>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#E5E5EA]">
          <button onClick={onCancel} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Abbrechen</button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700"
          >
            Löschen
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── OU Form Modal ────────────────────────────────────────────────────────────

function OUFormModal({
  onClose,
  onSuccess,
  ouTree,
  initial,
}: {
  onClose: () => void;
  onSuccess: (ou: OUNode) => void;
  ouTree: OUNode[];
  initial?: OUNode;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [parentId, setParentId] = useState<string>(initial?.parentId ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Flatten OU tree for parent selector
  function flattenOUs(nodes: OUNode[], depth = 0): { id: string; label: string }[] {
    const result: { id: string; label: string }[] = [];
    for (const n of nodes) {
      if (initial && n.id === initial.id) continue; // cannot set self as parent
      result.push({ id: n.id, label: '  '.repeat(depth) + n.name });
      result.push(...flattenOUs(n.children, depth + 1));
    }
    return result;
  }
  const flatOUs = flattenOUs(ouTree);

  async function submit() {
    if (!name.trim()) return;
    setLoading(true);
    setError('');
    try {
      let res;
      if (initial) {
        res = await groupApi.updateOU(initial.id, { name: name.trim(), description, parentId: parentId || null });
      } else {
        res = await groupApi.createOU({ name: name.trim(), description, parentId: parentId || null });
      }
      onSuccess({ ...res.data, children: res.data.children ?? [] });
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.error ?? 'Fehler beim Speichern');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-sm">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E5EA]">
          <h2 className="text-lg font-semibold text-gray-900">{initial ? 'OU bearbeiten' : 'Neue Organisationseinheit'}</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-[#F2F2F7]">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name <span className="text-red-500">*</span></label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="z. B. Engineering"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Beschreibung</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Optionale Beschreibung"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Übergeordnete OU</label>
            <select
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-[#0071E3] focus:border-[#0071E3]"
              value={parentId}
              onChange={e => setParentId(e.target.value)}
            >
              <option value="">— Keine (Root) —</option>
              {flatOUs.map(o => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#E5E5EA]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Abbrechen</button>
          <button
            onClick={submit}
            disabled={!name.trim() || loading}
            className="px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 disabled:opacity-50"
          >
            {loading ? 'Speichern…' : initial ? 'Speichern' : 'Erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Benutzer ────────────────────────────────────────────────────────────

function BenutzerTab({ ouFilter, onDemoData }: { ouFilter: string | null; onDemoData: () => void }) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [wizardGroups, setWizardGroups] = useState<ApiGroup[]>([]);
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showWizard, setShowWizard] = useState(false);
  const [toast, setToast] = useState('');

  const stableDemoData = useCallback(onDemoData, []);

  const fetchUsers = () => {
    setLoading(true);
    api.get('/api/users')
      .then(r => { if (Array.isArray(r.data)) setUsers(r.data); })
      .catch(() => {
        setUsers([]);
        stableDemoData();
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchUsers();
    groupApi.getGroups().then(r => { if (Array.isArray(r.data)) setWizardGroups(r.data); }).catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  }

  const filtered = useMemo(() => {
    return users.filter(u => {
      const matchesOU = ouFilter ? u.ou === ouFilter || u.ou.startsWith(ouFilter + '/') : true;
      const matchesSearch = !search || u.name.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase());
      return matchesOU && matchesSearch;
    });
  }, [users, search, ouFilter]);

  function handleDeactivate(id: string) {
    setUsers(us => us.map(u => u.id === id ? { ...u, status: 'inaktiv' as const } : u));
    setSelectedUser(null);
    showToast('Benutzer wurde deaktiviert.');
  }

  function handleDelete(id: string) {
    setUsers(us => us.filter(u => u.id !== id));
    setSelectedUser(null);
    showToast('Benutzer wurde gelöscht.');
  }

  return (
    <>
      {toast && (
        <div className="fixed bottom-6 right-6 bg-gray-900 text-white px-4 py-3 rounded-xl shadow-lg text-sm z-50">
          {toast}
        </div>
      )}

      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            className="w-full pl-9 pr-4 py-2 border border-[#E5E5EA] rounded-lg text-sm focus:ring-2 focus:ring-[#0071E3]"
            placeholder="Nach Name oder E-Mail suchen…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <button
          onClick={() => setShowWizard(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600 flex-shrink-0"
        >
          <PlusIcon className="w-4 h-4" />
          Nutzer hinzufügen
        </button>
      </div>

      <div className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
        {loading ? (
          <div className="space-y-2 p-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : users.length === 0 && !search && !ouFilter ? (
          <div className="text-center py-12 text-gray-400">
            <UserCircleIcon className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p className="font-medium">Keine Benutzer</p>
            <p className="text-sm mt-1">Erstellen Sie den ersten Benutzer mit dem Button oben.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#E5E5EA] text-left">
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Benutzer</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Rolle</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">OU</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Zuletzt aktiv</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {filtered.map(u => (
                <tr
                  key={u.id}
                  onClick={() => setSelectedUser(u)}
                  className="hover:bg-[#F2F2F7] cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <UserAvatar name={u.name} />
                      <div>
                        <p className="font-medium text-gray-900">{u.name}</p>
                        <p className="text-xs text-gray-500">{u.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3"><RoleBadge role={u.role} /></td>
                  <td className="px-4 py-3 text-gray-600">{u.ou}</td>
                  <td className="px-4 py-3"><StatusDot status={u.status} /></td>
                  <td className="px-4 py-3 text-gray-500">{u.lastActive}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-400 text-sm">
                    Keine Benutzer gefunden
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {showWizard && (
        <AddUserWizard
          onClose={() => setShowWizard(false)}
          onSuccess={u => { setUsers(us => [u, ...us]); showToast(`Benutzer „${u.name}" wurde angelegt.`); fetchUsers(); }}
          availableGroups={wizardGroups}
        />
      )}

      {selectedUser && (
        <>
          <div className="fixed inset-0 bg-transparent z-30" onClick={() => setSelectedUser(null)} />
          <UserDetailPanel
            user={selectedUser}
            onClose={() => setSelectedUser(null)}
            onDeactivate={handleDeactivate}
            onDelete={handleDelete}
          />
        </>
      )}
    </>
  );
}

// ─── Tab: Gruppen ─────────────────────────────────────────────────────────────

function GruppenTab() {
  const [groups, setGroups] = useState<ApiGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editTarget, setEditTarget] = useState<ApiGroup | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ApiGroup | null>(null);
  const [membersTarget, setMembersTarget] = useState<ApiGroup | null>(null);
  const [toast, setToast] = useState('');

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  }

  function fetchGroups() {
    setLoading(true);
    groupApi.getGroups()
      .then(r => { if (Array.isArray(r.data)) setGroups(r.data); })
      .catch(() => setGroups([]))
      .finally(() => setLoading(false));
  }

  useEffect(() => { fetchGroups(); }, []);

  async function handleDelete(g: ApiGroup) {
    try {
      await groupApi.deleteGroup(g.id);
      setGroups(gs => gs.filter(x => x.id !== g.id));
      showToast(`Gruppe „${g.name}" gelöscht.`);
    } catch {
      showToast('Fehler beim Löschen.');
    }
    setDeleteTarget(null);
  }

  function handleGroupSaved(g: ApiGroup) {
    setGroups(gs => {
      const idx = gs.findIndex(x => x.id === g.id);
      if (idx >= 0) {
        const copy = [...gs];
        copy[idx] = { ...copy[idx], ...g };
        return copy;
      }
      return [g, ...gs];
    });
    showToast(`Gruppe „${g.name}" gespeichert.`);
  }

  function openMembers(g: ApiGroup) {
    // Fetch full group details to get members
    groupApi.getGroup(g.id)
      .then(r => setMembersTarget(r.data))
      .catch(() => setMembersTarget(g));
  }

  return (
    <>
      {toast && (
        <div className="fixed bottom-6 right-6 bg-gray-900 text-white px-4 py-3 rounded-xl shadow-lg text-sm z-50">
          {toast}
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-gray-500">{groups.length} {groups.length === 1 ? 'Gruppe' : 'Gruppen'}</p>
        <button
          onClick={() => { setEditTarget(null); setShowModal(true); }}
          className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600"
        >
          <PlusIcon className="w-4 h-4" />
          Neue Gruppe
        </button>
      </div>

      <div className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
        {loading ? (
          <div className="space-y-2 p-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-14 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : groups.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <UserGroupIcon className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p className="font-medium">Keine Gruppen</p>
            <p className="text-sm mt-1">Erstellen Sie die erste Gruppe mit dem Button oben.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#E5E5EA] text-left">
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Beschreibung</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Mitglieder</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Aktionen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {groups.map(g => (
                <tr
                  key={g.id}
                  className="hover:bg-[#F2F2F7] cursor-pointer transition-colors"
                  onClick={() => openMembers(g)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                        <UserGroupIcon className="w-3.5 h-3.5 text-[#0071E3]" />
                      </div>
                      <span className="font-medium text-gray-900">{g.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500 max-w-xs truncate">{g.description || <span className="text-gray-300">—</span>}</td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-blue-50 text-[#0071E3] text-xs font-medium">
                      {g.memberCount ?? 0} Mitglieder
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => { setEditTarget(g); setShowModal(true); }}
                        className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-700 transition-colors"
                        title="Bearbeiten"
                      >
                        <PencilIcon className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(g)}
                        className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
                        title="Löschen"
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showModal && (
        <GroupFormModal
          onClose={() => { setShowModal(false); setEditTarget(null); }}
          onSuccess={handleGroupSaved}
          initial={editTarget ?? undefined}
        />
      )}

      {deleteTarget && (
        <ConfirmDeleteDialog
          title={`Gruppe löschen: ${deleteTarget.name}`}
          message={`Möchten Sie die Gruppe „${deleteTarget.name}" wirklich unwiderruflich löschen? Alle Mitgliedschaften werden entfernt.`}
          onConfirm={() => handleDelete(deleteTarget)}
          onCancel={() => setDeleteTarget(null)}
        />
      )}

      {membersTarget && (
        <>
          <div className="fixed inset-0 bg-transparent z-30" onClick={() => setMembersTarget(null)} />
          <GroupMembersPanel
            group={membersTarget}
            onClose={() => setMembersTarget(null)}
            onGroupUpdated={updated => {
              setGroups(gs => gs.map(g => g.id === updated.id ? { ...g, memberCount: updated.memberCount } : g));
              setMembersTarget(updated);
            }}
          />
        </>
      )}
    </>
  );
}

// ─── OU Row (flat table row with indentation) ─────────────────────────────────

function OURow({
  node,
  depth,
  onEdit,
  onDelete,
}: {
  node: OUNode;
  depth: number;
  onEdit: (ou: OUNode) => void;
  onDelete: (ou: OUNode) => void;
}) {
  return (
    <>
      <tr className="hover:bg-[#F2F2F7] transition-colors">
        <td className="px-4 py-3">
          <div className="flex items-center gap-2" style={{ paddingLeft: `${depth * 20}px` }}>
            {node.children.length > 0 ? (
              <FolderOpenIcon className="w-4 h-4 text-yellow-500 flex-shrink-0" />
            ) : (
              <FolderIcon className="w-4 h-4 text-yellow-400 flex-shrink-0" />
            )}
            <span className="font-medium text-gray-900">{node.name}</span>
            {depth > 0 && (
              <span className="text-xs text-gray-400 ml-1">Untergeordnet</span>
            )}
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">
          {node.description || <span className="text-gray-300">—</span>}
        </td>
        <td className="px-4 py-3 text-sm text-gray-500">
          {node.children.length > 0 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-yellow-50 text-yellow-700 text-xs font-medium">
              {node.children.length} Unter-OUs
            </span>
          )}
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1">
            <button
              onClick={() => onEdit(node)}
              className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-700 transition-colors"
              title="Bearbeiten"
            >
              <PencilIcon className="w-4 h-4" />
            </button>
            <button
              onClick={() => onDelete(node)}
              className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
              title="Löschen"
            >
              <TrashIcon className="w-4 h-4" />
            </button>
          </div>
        </td>
      </tr>
      {node.children.map(child => (
        <OURow key={child.id} node={child} depth={depth + 1} onEdit={onEdit} onDelete={onDelete} />
      ))}
    </>
  );
}

// ─── Tab: Organisationseinheiten ──────────────────────────────────────────────

function OUTab({ onFilterByOU }: { onFilterByOU: (ou: string | null) => void }) {
  const [ouTree, setOuTree] = useState<OUNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editTarget, setEditTarget] = useState<OUNode | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<OUNode | null>(null);
  const [selectedOU, setSelectedOU] = useState<string | null>(null);
  const [toast, setToast] = useState('');

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  }

  function fetchOUs() {
    setLoading(true);
    groupApi.getOUs()
      .then(r => { if (Array.isArray(r.data)) setOuTree(r.data); })
      .catch(() => setOuTree([]))
      .finally(() => setLoading(false));
  }

  useEffect(() => { fetchOUs(); }, []);

  // Count total OUs in tree
  function countOUs(nodes: OUNode[]): number {
    return nodes.reduce((acc, n) => acc + 1 + countOUs(n.children), 0);
  }

  function handleSelect(name: string | null) {
    setSelectedOU(name);
    onFilterByOU(name);
  }

  function handleOUSaved(ou: OUNode) {
    // Refetch to get updated tree
    fetchOUs();
    showToast(`OU „${ou.name}" gespeichert.`);
  }

  async function handleDelete(ou: OUNode) {
    try {
      await groupApi.deleteOU(ou.id);
      fetchOUs();
      showToast(`OU „${ou.name}" gelöscht.`);
    } catch {
      showToast('Fehler beim Löschen.');
    }
    setDeleteTarget(null);
  }

  return (
    <>
      {toast && (
        <div className="fixed bottom-6 right-6 bg-gray-900 text-white px-4 py-3 rounded-xl shadow-lg text-sm z-50">
          {toast}
        </div>
      )}

      <div className="flex gap-6">
        {/* Left: OU tree sidebar for filtering */}
        <div className="w-56 flex-shrink-0">
          <div className="bg-white rounded-xl border border-[#E5E5EA] p-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide px-2 mb-2">OU-Baum</p>
            {loading ? (
              <div className="space-y-1 px-2">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="h-6 bg-gray-100 rounded animate-pulse" />
                ))}
              </div>
            ) : ouTree.length === 0 ? (
              <p className="text-xs text-gray-400 px-2">Keine OUs</p>
            ) : (
              ouTree.map(node => (
                <OUTreeNode key={node.id} node={node} level={0} selectedOU={selectedOU} onSelect={handleSelect} />
              ))
            )}
          </div>
        </div>

        {/* Right: OU management table */}
        <div className="flex-1">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-gray-500">{countOUs(ouTree)} Organisationseinheiten</p>
            <button
              onClick={() => { setEditTarget(null); setShowModal(true); }}
              className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-blue-600"
            >
              <PlusIcon className="w-4 h-4" />
              Neue OU
            </button>
          </div>

          <div className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
            {loading ? (
              <div className="space-y-2 p-4">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="h-12 bg-gray-100 rounded animate-pulse" />
                ))}
              </div>
            ) : ouTree.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <BuildingOfficeIcon className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p className="font-medium">Keine Organisationseinheiten</p>
                <p className="text-sm mt-1">Erstellen Sie die erste OU mit dem Button oben.</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#E5E5EA] text-left">
                    <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Beschreibung</th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Unterstruktur</th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Aktionen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {ouTree.map(node => (
                    <OURow
                      key={node.id}
                      node={node}
                      depth={0}
                      onEdit={ou => { setEditTarget(ou); setShowModal(true); }}
                      onDelete={ou => setDeleteTarget(ou)}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Filter hint when OU is selected */}
          {selectedOU && (
            <div className="mt-4 flex items-center gap-2 p-3 bg-blue-50 border border-blue-100 rounded-xl text-sm text-[#0071E3]">
              <FolderOpenIcon className="w-4 h-4 flex-shrink-0" />
              <span>Benutzer-Tab gefiltert nach: <strong>{selectedOU}</strong></span>
              <button
                onClick={() => handleSelect(null)}
                className="ml-auto text-xs underline hover:no-underline"
              >
                Filter aufheben
              </button>
            </div>
          )}
        </div>
      </div>

      {showModal && (
        <OUFormModal
          onClose={() => { setShowModal(false); setEditTarget(null); }}
          onSuccess={handleOUSaved}
          ouTree={ouTree}
          initial={editTarget ?? undefined}
        />
      )}

      {deleteTarget && (
        <ConfirmDeleteDialog
          title={`OU löschen: ${deleteTarget.name}`}
          message={`Möchten Sie die Organisationseinheit „${deleteTarget.name}" wirklich löschen? Untergeordnete OUs bleiben erhalten.`}
          onConfirm={() => handleDelete(deleteTarget)}
          onCancel={() => setDeleteTarget(null)}
        />
      )}
    </>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export default function UsersView() {
  const [activeTab, setActiveTab] = useState<'benutzer' | 'gruppen' | 'ou'>('benutzer');
  const [ouFilter, setOuFilter] = useState<string | null>(null);
  const [usingDemoData, setUsingDemoData] = useState(false);

  const tabs = [
    { id: 'benutzer', label: 'Benutzer' },
    { id: 'gruppen', label: 'Gruppen' },
    { id: 'ou', label: 'Organisationseinheiten' },
  ] as const;

  function handleOUFilter(ou: string | null) {
    setOuFilter(ou);
    if (ou) setActiveTab('benutzer');
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {usingDemoData && (
        <div className="mx-6 mt-4 p-3 bg-yellow-900/50 border border-yellow-600 rounded-lg flex items-center gap-2 text-yellow-300 text-sm">
          <span className="text-yellow-400">!</span>
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Benutzer & Verzeichnis</h1>
        <p className="text-sm text-gray-500 mt-1">Benutzer, Gruppen und Organisationseinheiten verwalten</p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 mb-6 border-b border-[#E5E5EA]">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === t.id
                ? 'border-[#0071E3] text-[#0071E3]'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {t.label}
          </button>
        ))}
        {ouFilter && activeTab === 'benutzer' && (
          <div className="ml-auto flex items-center">
            <span className="text-xs text-[#0071E3] bg-blue-50 px-3 py-1 rounded-full flex items-center gap-1">
              <FolderIcon className="w-3.5 h-3.5" />
              Gefiltert: {ouFilter}
              <button onClick={() => setOuFilter(null)} className="ml-1 hover:text-blue-800">
                <XMarkIcon className="w-3.5 h-3.5" />
              </button>
            </span>
          </div>
        )}
      </div>

      {/* Tab Content */}
      {activeTab === 'benutzer' && <BenutzerTab ouFilter={ouFilter} onDemoData={() => setUsingDemoData(true)} />}
      {activeTab === 'gruppen' && <GruppenTab />}
      {activeTab === 'ou' && <OUTab onFilterByOU={handleOUFilter} />}
    </div>
  );
}
