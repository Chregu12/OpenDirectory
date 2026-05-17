'use client';

import { useState, useEffect, useMemo } from 'react';
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
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

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

interface Group {
  id: string;
  name: string;
  ou: string;
  memberCount: number;
  policies: string[];
}

interface OUNode {
  id: string;
  name: string;
  children: OUNode[];
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

const DEMO_GROUPS: Group[] = [
  { id: 'g1', name: 'Engineering', ou: 'Engineering', memberCount: 12, policies: ['CIS Windows 11 L1', 'Update Ring: Beta'] },
  { id: 'g2', name: 'IT', ou: 'IT', memberCount: 5, policies: ['CIS Ubuntu 22 L2', 'Update Ring: Dev'] },
  { id: 'g3', name: 'Marketing', ou: 'Marketing', memberCount: 8, policies: ['Update Ring: Stable'] },
];

const DEMO_OU_TREE: OUNode[] = [
  {
    id: 'ou-root', name: 'Firma', children: [
      { id: 'ou-it', name: 'IT', children: [] },
      {
        id: 'ou-eng', name: 'Engineering', children: [
          { id: 'ou-backend', name: 'Backend', children: [] },
          { id: 'ou-frontend', name: 'Frontend', children: [] },
        ]
      },
      { id: 'ou-marketing', name: 'Marketing', children: [] },
    ]
  }
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

// ─── OU Tree Node ─────────────────────────────────────────────────────────────

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
        className={`w-full flex items-center gap-1 px-2 py-1.5 rounded text-sm text-left hover:bg-gray-100 ${isSelected ? 'bg-indigo-50 text-indigo-700 font-medium' : 'text-gray-700'}`}
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

function AddUserWizard({ onClose, onSuccess }: { onClose: () => void; onSuccess: (u: User) => void }) {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    name: '', email: '', role: 'user' as User['role'],
    group: '', ou: 'IT',
    notify: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function set(k: string, v: string | boolean) {
    setForm(f => ({ ...f, [k]: v }));
  }

  async function submit() {
    setLoading(true);
    setError('');
    try {
      await api.post('/api/users', { name: form.name, email: form.email, role: form.role, ou: form.ou, group: form.group, notify: form.notify });
    } catch (_) {
      // API unavailable — proceed with demo
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
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Nutzer hinzufügen</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-gray-100">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Steps indicator */}
        <div className="flex items-center px-6 pt-4 gap-2">
          {[1, 2, 3].map(s => (
            <div key={s} className="flex items-center gap-2 flex-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0 ${step >= s ? 'bg-indigo-600 text-white' : 'bg-gray-200 text-gray-500'}`}>
                {s}
              </div>
              {s < 3 && <div className={`flex-1 h-0.5 ${step > s ? 'bg-indigo-600' : 'bg-gray-200'}`} />}
            </div>
          ))}
        </div>

        <div className="px-6 py-4 space-y-4">
          {step === 1 && (
            <>
              <p className="text-sm font-medium text-gray-500">Schritt 1: Identität</p>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                <input className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500" value={form.name} onChange={e => set('name', e.target.value)} placeholder="Max Mustermann" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">E-Mail</label>
                <input type="email" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500" value={form.email} onChange={e => set('email', e.target.value)} placeholder="max@firma.local" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rolle</label>
                <select className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500" value={form.role} onChange={e => set('role', e.target.value)}>
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
                <select className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500" value={form.group} onChange={e => set('group', e.target.value)}>
                  <option value="">Keine Gruppe</option>
                  {DEMO_GROUPS.map(g => <option key={g.id} value={g.name}>{g.name}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Organisationseinheit (OU)</label>
                <select className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500" value={form.ou} onChange={e => set('ou', e.target.value)}>
                  {OU_OPTIONS.map(ou => <option key={ou} value={ou}>{ou}</option>)}
                </select>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <p className="text-sm font-medium text-gray-500">Schritt 3: Benachrichtigung</p>
              <div className="flex items-center gap-3 p-4 bg-gray-50 rounded-lg">
                <input type="checkbox" id="notify" checked={form.notify} onChange={e => set('notify', e.target.checked)} className="w-4 h-4 rounded text-indigo-600" />
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

          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200">
          <button onClick={step === 1 ? onClose : () => setStep(s => s - 1)} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">
            {step === 1 ? 'Abbrechen' : 'Zurück'}
          </button>
          {step < 3 ? (
            <button
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && (!form.name || !form.email)}
              className="px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Weiter
            </button>
          ) : (
            <button onClick={submit} disabled={loading} className="px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 disabled:opacity-50">
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
    <div className="fixed inset-y-0 right-0 w-96 bg-white shadow-2xl z-40 flex flex-col border-l border-gray-200">
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div className="flex items-center gap-3">
          <UserAvatar name={user.name} />
          <div>
            <p className="font-semibold text-gray-900 text-sm">{user.name}</p>
            <p className="text-xs text-gray-500">{user.email}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-gray-100">
          <XMarkIcon className="w-5 h-5 text-gray-500" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Role & Status */}
        <div className="flex items-center gap-3">
          <RoleBadge role={user.role} />
          <StatusDot status={user.status} />
        </div>

        {/* Groups */}
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

        {/* Devices */}
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

        {/* App Assignments */}
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

        {/* Meta */}
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

      <div className="px-6 py-4 border-t border-gray-200 flex gap-3">
        <button
          onClick={() => onDeactivate(user.id)}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 text-sm rounded-lg hover:bg-gray-50"
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

// ─── Create Group Modal ───────────────────────────────────────────────────────

function CreateGroupModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: (g: Group) => void }) {
  const [name, setName] = useState('');
  const [ou, setOu] = useState('IT');
  const [description, setDescription] = useState('');

  function submit() {
    const g: Group = { id: `g-${Date.now()}`, name, ou, memberCount: 0, policies: [] };
    onSuccess(g);
    onClose();
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-sm">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Gruppe erstellen</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-gray-100">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
            <input className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" value={name} onChange={e => setName(e.target.value)} placeholder="Gruppenname" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Organisationseinheit</label>
            <select className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" value={ou} onChange={e => setOu(e.target.value)}>
              {OU_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Beschreibung (optional)</label>
            <input className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" value={description} onChange={e => setDescription(e.target.value)} placeholder="Kurze Beschreibung" />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-gray-200">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600">Abbrechen</button>
          <button onClick={submit} disabled={!name} className="px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 disabled:opacity-50">Erstellen</button>
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Benutzer ────────────────────────────────────────────────────────────

function BenutzerTab({ ouFilter, onDemoData }: { ouFilter: string | null; onDemoData: () => void }) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showWizard, setShowWizard] = useState(false);
  const [toast, setToast] = useState('');

  useEffect(() => {
    api.get('/api/users')
      .then(r => { if (Array.isArray(r.data)) setUsers(r.data); })
      .catch(() => {
        // Show empty list with error, not fake data
        setUsers([]);
        onDemoData();
      })
      .finally(() => setLoading(false));
  }, [onDemoData]);

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
            className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
            placeholder="Nach Name oder E-Mail suchen…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <button
          onClick={() => setShowWizard(true)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 flex-shrink-0"
        >
          <PlusIcon className="w-4 h-4" />
          Nutzer hinzufügen
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left">
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
                className="hover:bg-gray-50 cursor-pointer transition-colors"
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
      </div>

      {showWizard && (
        <AddUserWizard
          onClose={() => setShowWizard(false)}
          onSuccess={u => { setUsers(us => [u, ...us]); showToast(`Benutzer „${u.name}" wurde angelegt.`); }}
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
  const [groups, setGroups] = useState<Group[]>(DEMO_GROUPS);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    api.get('/api/groups').then(r => { if (Array.isArray(r.data)) setGroups(r.data); }).catch(() => {});
  }, []);

  return (
    <>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-gray-500">{groups.length} Gruppen</p>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700"
        >
          <PlusIcon className="w-4 h-4" />
          Gruppe erstellen
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left">
              <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">OU</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Mitglieder</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Richtlinien</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Aktionen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {groups.map(g => (
              <tr key={g.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3 font-medium text-gray-900">{g.name}</td>
                <td className="px-4 py-3 text-gray-600">{g.ou}</td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 text-xs font-medium">
                    {g.memberCount} Mitglieder
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {g.policies.map(p => (
                      <span key={p} className="px-2 py-0.5 bg-gray-100 text-gray-600 text-xs rounded">{p}</span>
                    ))}
                    {g.policies.length === 0 && <span className="text-gray-400 text-xs">Keine</span>}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => setGroups(gs => gs.filter(x => x.id !== g.id))}
                    className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <CreateGroupModal
          onClose={() => setShowModal(false)}
          onSuccess={g => setGroups(gs => [...gs, g])}
        />
      )}
    </>
  );
}

// ─── Tab: Organisationseinheiten ──────────────────────────────────────────────

function OUTab({ onFilterByOU }: { onFilterByOU: (ou: string | null) => void }) {
  const [ouTree, setOuTree] = useState<OUNode[]>(DEMO_OU_TREE);
  const [selectedOU, setSelectedOU] = useState<string | null>(null);

  useEffect(() => {
    api.get('/api/ous').then(r => { if (Array.isArray(r.data)) setOuTree(r.data); }).catch(() => {});
  }, []);

  function handleSelect(name: string | null) {
    setSelectedOU(name);
    onFilterByOU(name);
  }

  return (
    <div className="flex gap-6">
      <div className="w-64 flex-shrink-0">
        <div className="bg-white rounded-xl border border-gray-200 p-3">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide px-2 mb-2">OU-Baum</p>
          {ouTree.map(node => (
            <OUTreeNode key={node.id} node={node} level={0} selectedOU={selectedOU} onSelect={handleSelect} />
          ))}
        </div>
      </div>

      <div className="flex-1">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          {selectedOU ? (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">{selectedOU}</h3>
                <button onClick={() => handleSelect(null)} className="text-sm text-indigo-600 hover:text-indigo-700">
                  Filter aufheben
                </button>
              </div>
              <p className="text-sm text-gray-500">
                Benutzer in dieser OU werden im Tab „Benutzer" gefiltert angezeigt.
              </p>
              <div className="mt-4 flex gap-2">
                <span className="inline-flex items-center px-3 py-1 bg-indigo-50 text-indigo-700 text-sm rounded-lg">
                  <FolderOpenIcon className="w-4 h-4 mr-1.5" />
                  {selectedOU}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <FolderIcon className="w-10 h-10 text-gray-300 mx-auto mb-3" />
              <p className="text-sm text-gray-500">OU im Baum auswählen, um Benutzer zu filtern</p>
            </div>
          )}
        </div>
      </div>
    </div>
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
          <span className="text-yellow-400">⚠</span>
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Benutzer & Verzeichnis</h1>
        <p className="text-sm text-gray-500 mt-1">Benutzer, Gruppen und Organisationseinheiten verwalten</p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 mb-6 border-b border-gray-200">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === t.id
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {t.label}
          </button>
        ))}
        {ouFilter && activeTab === 'benutzer' && (
          <div className="ml-auto flex items-center">
            <span className="text-xs text-indigo-600 bg-indigo-50 px-3 py-1 rounded-full flex items-center gap-1">
              <FolderIcon className="w-3.5 h-3.5" />
              Gefiltert: {ouFilter}
              <button onClick={() => setOuFilter(null)} className="ml-1 hover:text-indigo-800">
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
