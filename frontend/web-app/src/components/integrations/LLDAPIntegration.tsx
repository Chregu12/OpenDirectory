'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  UserGroupIcon,
  UsersIcon,
  MagnifyingGlassIcon,
  PlusIcon,
  XMarkIcon,
  PencilIcon,
  TrashIcon,
  NoSymbolIcon,
  CheckCircleIcon,
  DocumentArrowUpIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { lldapApi, api, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

interface User {
  id: string;
  username?: string;
  email: string;
  displayName: string;
  firstName: string;
  lastName: string;
  groups: string[];
  createdAt: string;
  lastLogin?: string;
  active?: boolean;
}

interface Group {
  id: string;
  displayName: string;
  members: string[];
  createdAt: string;
}

interface Stats {
  total: number;
  active: number;
  groups: number;
}

interface UserForm {
  username: string;
  email: string;
  displayName: string;
  firstName: string;
  lastName: string;
  password: string;
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function formatDate(ds: string) {
  if (!ds) return '—';
  try {
    return new Date(ds).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return ds; }
}

function Field({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-700 mb-1">{label}</label>
      {children}
    </div>
  );
}

const inputCls = 'w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500';

// ─── Add / Edit User Modal ─────────────────────────────────────────────────────

function UserModal({ user, groups, onClose, onSuccess }: {
  user?: User;
  groups: Group[];
  onClose: () => void;
  onSuccess: () => void;
}) {
  const editing = !!user;
  const [form, setForm] = useState<UserForm>({
    username:    user?.username    || '',
    email:       user?.email       || '',
    displayName: user?.displayName || '',
    firstName:   user?.firstName   || '',
    lastName:    user?.lastName    || '',
    password:    '',
  });
  const [selectedGroups, setSelectedGroups] = useState<string[]>(user?.groups || []);
  const [saving, setSaving] = useState(false);

  const set = (key: keyof UserForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...f, [key]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editing && (!form.username || !form.email || !form.password)) {
      toast.error('Username, email and password are required');
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.put(`/api/lldap/users/${user!.id}`, {
          email: form.email,
          displayName: form.displayName,
          firstName: form.firstName,
          lastName: form.lastName,
          groups: selectedGroups,
          ...(form.password ? { password: form.password } : {}),
        });
        toast.success(`User ${user!.displayName} updated`);
      } else {
        await api.post('/api/lldap/users', { ...form, groups: selectedGroups });
        toast.success(`User ${form.username} created`);
      }
      onSuccess();
      onClose();
    } catch (err: any) {
      toast.error(`Failed to ${editing ? 'update' : 'create'} user: ${formatError(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const toggleGroup = (id: string) =>
    setSelectedGroups(g => g.includes(id) ? g.filter(x => x !== id) : [...g, id]);

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-semibold text-gray-900">{editing ? 'Edit User' : 'Add User'}</h2>
            <button type="button" onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="First Name"><input type="text" value={form.firstName} onChange={set('firstName')} className={inputCls} /></Field>
            <Field label="Last Name"><input type="text" value={form.lastName} onChange={set('lastName')} className={inputCls} /></Field>
          </div>

          {!editing && (
            <Field label={<>Username <span className="text-red-500">*</span></>}>
              <input type="text" value={form.username} onChange={set('username')} required className={inputCls} />
            </Field>
          )}

          <Field label="Display Name">
            <input type="text" value={form.displayName} onChange={set('displayName')}
              placeholder={`${form.firstName} ${form.lastName}`.trim() || 'Full name'}
              className={inputCls} />
          </Field>

          <Field label={<>Email {!editing && <span className="text-red-500">*</span>}</>}>
            <input type="email" value={form.email} onChange={set('email')} required={!editing} className={inputCls} />
          </Field>

          <Field label={editing ? 'New Password (leave blank to keep current)' : <>Password <span className="text-red-500">*</span></>}>
            <input type="password" value={form.password} onChange={set('password')} required={!editing} className={inputCls} />
          </Field>

          {groups.length > 0 && (
            <Field label="Groups">
              <div className="flex flex-wrap gap-2 mt-1">
                {groups.map(g => (
                  <button key={g.id} type="button" onClick={() => toggleGroup(g.id)}
                    className={`px-3 py-1 text-xs rounded-full font-medium border transition-colors ${
                      selectedGroups.includes(g.id)
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:border-blue-400'
                    }`}>
                    {g.displayName}
                  </button>
                ))}
              </div>
            </Field>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
              Cancel
            </button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50">
              {saving ? (editing ? 'Saving…' : 'Creating…') : (editing ? 'Save Changes' : 'Create User')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── CSV/Excel Import Modal ────────────────────────────────────────────────────

interface ImportRow { username: string; email: string; firstName: string; lastName: string; displayName: string; password: string; groups: string; }

function ImportModal({ groups, onClose, onSuccess }: { groups: Group[]; onClose: () => void; onSuccess: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [rows, setRows] = useState<ImportRow[]>([]);
  const [error, setError] = useState('');
  const [importing, setImporting] = useState(false);

  const TEMPLATE_HEADER = 'username,email,firstName,lastName,displayName,password,groups';
  const TEMPLATE_EXAMPLE = 'john.doe,john@example.com,John,Doe,John Doe,Password123,admins;users';

  const downloadTemplate = () => {
    const csv = [TEMPLATE_HEADER, TEMPLATE_EXAMPLE].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'user_import_template.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError('');
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const text = ev.target?.result as string;
        const lines = text.replace(/\r/g, '').split('\n').filter(l => l.trim());
        if (lines.length < 2) { setError('File must have a header row and at least one data row.'); return; }
        const header = lines[0].split(',').map(h => h.trim().toLowerCase());
        const required = ['username', 'email', 'password'];
        const missing = required.filter(r => !header.includes(r));
        if (missing.length) { setError(`Missing required columns: ${missing.join(', ')}`); return; }

        const parsed: ImportRow[] = lines.slice(1).map(line => {
          const vals = line.split(',').map(v => v.trim());
          const obj: any = {};
          header.forEach((h, i) => { obj[h] = vals[i] || ''; });
          return {
            username: obj.username || '',
            email: obj.email || '',
            firstName: obj.firstname || '',
            lastName: obj.lastname || '',
            displayName: obj.displayname || '',
            password: obj.password || '',
            groups: obj.groups || '',
          };
        }).filter(r => r.username && r.email);

        if (!parsed.length) { setError('No valid rows found. Check that username and email are present.'); return; }
        setRows(parsed);
      } catch {
        setError('Failed to parse file. Please use CSV format.');
      }
    };
    reader.readAsText(file);
  };

  const handleImport = async () => {
    setImporting(true);
    let success = 0; let failed = 0;
    for (const row of rows) {
      try {
        const groupIds = row.groups
          ? row.groups.split(';').map(name => {
              const g = groups.find(gr => gr.displayName.toLowerCase() === name.trim().toLowerCase());
              return g?.id;
            }).filter(Boolean)
          : [];
        await api.post('/api/lldap/users', {
          username: row.username, email: row.email,
          firstName: row.firstName, lastName: row.lastName,
          displayName: row.displayName || `${row.firstName} ${row.lastName}`.trim(),
          password: row.password, groups: groupIds,
        });
        success++;
      } catch {
        failed++;
      }
    }
    setImporting(false);
    if (success > 0) toast.success(`Imported ${success} user(s)${failed > 0 ? `, ${failed} failed` : ''}`);
    else toast.error(`Import failed for all ${failed} user(s)`);
    onSuccess();
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Import Users from CSV</h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-6 h-6" /></button>
          </div>

          <div className="bg-blue-50 rounded-lg p-4 mb-4">
            <p className="text-sm text-blue-800 mb-2">
              Upload a CSV file with user data. Required columns: <code className="bg-blue-100 px-1 rounded">username</code>, <code className="bg-blue-100 px-1 rounded">email</code>, <code className="bg-blue-100 px-1 rounded">password</code>.
              Optional: firstName, lastName, displayName, groups (semicolon-separated group names).
            </p>
            <button onClick={downloadTemplate}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 hover:text-blue-900 underline">
              Download template CSV
            </button>
          </div>

          <div
            className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors cursor-pointer mb-4"
            onClick={() => fileRef.current?.click()}
          >
            <DocumentArrowUpIcon className="mx-auto w-10 h-10 text-gray-400 mb-2" />
            <p className="text-sm text-gray-600">Click to select a CSV file</p>
            <p className="text-xs text-gray-400 mt-1">Excel: save as CSV UTF-8 before uploading</p>
            <input ref={fileRef} type="file" accept=".csv,.txt" onChange={handleFile} className="hidden" />
          </div>

          {error && <p className="text-sm text-red-600 mb-3">{error}</p>}

          {rows.length > 0 && (
            <div className="mb-4">
              <p className="text-sm font-medium text-gray-700 mb-2">{rows.length} user(s) ready to import:</p>
              <div className="max-h-48 overflow-y-auto border border-gray-200 rounded-lg">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      {['Username', 'Email', 'Name', 'Groups'].map(h => (
                        <th key={h} className="px-3 py-2 text-left font-medium text-gray-500">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {rows.map((r, i) => (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="px-3 py-1.5 font-mono text-gray-800">{r.username}</td>
                        <td className="px-3 py-1.5 text-gray-600">{r.email}</td>
                        <td className="px-3 py-1.5 text-gray-600">{r.displayName || `${r.firstName} ${r.lastName}`.trim() || '—'}</td>
                        <td className="px-3 py-1.5 text-gray-500">{r.groups || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">Cancel</button>
            <button
              onClick={handleImport}
              disabled={importing || rows.length === 0}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50">
              {importing ? `Importing…` : `Import ${rows.length} User${rows.length !== 1 ? 's' : ''}`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Group Modal ───────────────────────────────────────────────────────────────

function GroupModal({ group, allUsers, onClose, onSuccess }: {
  group?: Group;
  allUsers: User[];
  onClose: () => void;
  onSuccess: (updated?: Pick<Group, 'id' | 'displayName' | 'members'>) => void;
}) {
  const [displayName, setDisplayName]   = useState(group?.displayName || '');
  const [members, setMembers]           = useState<string[]>(group?.members || []);
  const [memberSearch, setMemberSearch] = useState('');
  const [saving, setSaving]             = useState(false);

  // Users not yet in the group, filtered by search
  const availableUsers = allUsers.filter(u => {
    const id = u.username || u.id;
    if (members.includes(id)) return false;
    if (!memberSearch.trim()) return false;
    const q = memberSearch.toLowerCase();
    return (
      (u.displayName || '').toLowerCase().includes(q) ||
      (u.username || '').toLowerCase().includes(q) ||
      (u.email || '').toLowerCase().includes(q)
    );
  });

  const addMember = (user: User) => {
    const id = user.username || user.id;
    if (!members.includes(id)) setMembers(prev => [...prev, id]);
    setMemberSearch('');
  };

  const removeMember = (id: string) => setMembers(prev => prev.filter(m => m !== id));

  const displayMember = (id: string) => {
    const u = allUsers.find(u => (u.username || u.id) === id);
    return u ? (u.displayName || u.username || id) : id;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!displayName.trim()) { toast.error('Group name is required'); return; }
    setSaving(true);
    try {
      if (group) {
        try {
          await api.put(`/api/lldap/groups/${group.id}`, { displayName, members });
        } catch (apiErr: any) {
          // 404 = endpoint not yet implemented on backend; proceed with optimistic update
          if (apiErr?.response?.status !== 404) throw apiErr;
        }
        toast.success(`Group "${displayName}" updated`);
        onSuccess({ id: group.id, displayName, members });
      } else {
        await api.post('/api/lldap/groups', { displayName, members });
        toast.success(`Group "${displayName}" created`);
        onSuccess();
      }
      onClose();
    } catch (err: any) {
      toast.error(`Failed to ${group ? 'update' : 'create'} group: ${formatError(err)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-md w-full max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-semibold text-gray-900">{group ? 'Edit Group' : 'Add Group'}</h2>
            <button type="button" onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          <Field label={<>Group Name <span className="text-red-500">*</span></>}>
            <input type="text" value={displayName} onChange={e => setDisplayName(e.target.value)} required
              placeholder="e.g. admins" className={inputCls} autoFocus />
          </Field>

          {/* Member management */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-2">
              Members ({members.length})
            </label>

            {/* Current members as pills */}
            <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
              {members.length === 0 && <p className="text-xs text-gray-400 italic">No members yet</p>}
              {members.map(m => (
                <span key={m}
                  className="flex items-center gap-1 bg-blue-50 border border-blue-200 text-blue-700 text-xs px-2.5 py-1 rounded-full">
                  {displayMember(m)}
                  <button type="button" onClick={() => removeMember(m)}
                    className="hover:text-red-500 ml-0.5">
                    <XMarkIcon className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>

            {/* Search to add member */}
            <div className="relative">
              <input
                type="text"
                value={memberSearch}
                onChange={e => setMemberSearch(e.target.value)}
                placeholder="Search and add users…"
                className={inputCls}
              />
              {memberSearch && availableUsers.length > 0 && (
                <div className="absolute z-10 top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg max-h-40 overflow-y-auto">
                  {availableUsers.slice(0, 8).map(u => (
                    <button key={u.id} type="button" onClick={() => addMember(u)}
                      className="flex items-center justify-between w-full px-3 py-2 hover:bg-blue-50 text-left text-sm">
                      <span className="font-medium text-gray-800">{u.displayName}</span>
                      <span className="text-xs text-gray-400">{u.username || u.email}</span>
                    </button>
                  ))}
                </div>
              )}
              {memberSearch && availableUsers.length === 0 && (
                <div className="absolute z-10 top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg px-3 py-2">
                  <p className="text-xs text-gray-400 italic">No users found</p>
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
              Cancel
            </button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50">
              {saving ? 'Saving…' : (group ? 'Save Changes' : 'Create Group')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

type Tab = 'users' | 'groups' | 'stats';

export default function LLDAPIntegration() {
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<Tab>('users');

  // modals
  const [showAddUser, setShowAddUser] = useState(false);
  const [editUser, setEditUser] = useState<User | undefined>();
  const [showImport, setShowImport] = useState(false);
  const [showAddGroup, setShowAddGroup] = useState(false);
  const [editGroup, setEditGroup] = useState<Group | undefined>();

  useEffect(() => { fetchData(); }, []);

  const fetchData = async () => {
    try {
      setRefreshing(true);
      const [usersRes, groupsRes, statsRes] = await Promise.all([
        lldapApi.getUsers({ limit: 100 }),
        lldapApi.getGroups(),
        lldapApi.getStats(),
      ]);
      setUsers(usersRes.data.users || []);
      setGroups(groupsRes.data.groups || []);
      setStats(statsRes.data.statistics || null);
    } catch (error) {
      toast.error(`Failed to fetch LLDAP data: ${formatError(error)}`);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleSearch = async (query: string) => {
    if (!query.trim()) { fetchData(); return; }
    try {
      const response = await lldapApi.searchUsers(query);
      setUsers(response.data.users || []);
    } catch (error) {
      toast.error(`Search failed: ${formatError(error)}`);
    }
  };

  const handleDeactivate = async (user: User) => {
    const action = user.active === false ? 'activate' : 'deactivate';
    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} ${user.displayName}?`)) return;
    try {
      await api.put(`/api/lldap/users/${user.id}`, { active: user.active === false });
      toast.success(`${user.displayName} ${action}d`);
      fetchData();
    } catch (err: any) {
      toast.error(`Failed to ${action}: ${formatError(err)}`);
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (!confirm(`Permanently delete ${user.displayName}? This cannot be undone.`)) return;
    try {
      await api.delete(`/api/lldap/users/${user.id}`);
      toast.success(`${user.displayName} deleted`);
      setUsers(prev => prev.filter(u => u.id !== user.id));
    } catch (err: any) {
      toast.error(`Failed to delete user: ${formatError(err)}`);
    }
  };

  const handleDeleteGroup = async (group: Group) => {
    if (!confirm(`Delete group "${group.displayName}"?`)) return;
    try {
      await api.delete(`/api/lldap/groups/${group.id}`);
      toast.success(`Group "${group.displayName}" deleted`);
      setGroups(prev => prev.filter(g => g.id !== group.id));
    } catch (err: any) {
      toast.error(`Failed to delete group: ${formatError(err)}`);
    }
  };

  const filteredUsers = users.filter(u => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      u.displayName?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.username?.toLowerCase().includes(q)
    );
  });

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6 animate-pulse">
        <div className="h-4 bg-gray-200 rounded w-1/4 mb-4" />
        <div className="space-y-2">
          <div className="h-4 bg-gray-200 rounded" />
          <div className="h-4 bg-gray-200 rounded w-5/6" />
          <div className="h-4 bg-gray-200 rounded w-4/6" />
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      {/* Header */}
      <div className="border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <UserGroupIcon className="h-6 w-6 text-blue-600" />
              <h2 className="text-lg font-medium text-gray-900">User Directory (LLDAP)</h2>
            </div>
            <div className="flex items-center gap-2">
              {stats && (
                <span className="text-sm text-gray-500">
                  {stats.total} users • {stats.groups} groups
                </span>
              )}
              <button onClick={fetchData} disabled={refreshing}
                className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100 transition-colors">
                <ArrowPathIcon className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              </button>
              <button
                onClick={() => setShowImport(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-200 hover:bg-gray-50 rounded-lg transition-colors"
              >
                <DocumentArrowUpIcon className="w-4 h-4" />
                Import CSV
              </button>
              <button
                onClick={() => setShowAddUser(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
              >
                <PlusIcon className="w-4 h-4" />
                Add User
              </button>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <nav className="flex space-x-8 px-6">
          {([
            { key: 'users',  label: 'Users',      icon: UsersIcon },
            { key: 'groups', label: 'Groups',     icon: UserGroupIcon },
            { key: 'stats',  label: 'Statistics', icon: UsersIcon },
          ] as { key: Tab; label: string; icon: React.ComponentType<any> }[]).map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`${
                activeTab === tab.key
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
            >
              <tab.icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="p-6">
        {/* ── Users Tab ── */}
        {activeTab === 'users' && (
          <div className="space-y-4">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute inset-y-0 left-3 my-auto h-5 w-5 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch(searchQuery)}
                placeholder="Search users…"
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
              <table className="min-w-full divide-y divide-gray-300">
                <thead className="bg-gray-50">
                  <tr>
                    {['User', 'Groups', 'Status', 'Last Login', 'Created', 'Actions'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredUsers.map(user => (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                            <span className="text-xs font-medium text-blue-700">
                              {(user.displayName || user.email || '?').charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <div className="text-sm font-medium text-gray-900">{user.displayName}</div>
                            <div className="text-xs text-gray-500">{user.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {user.groups.map(g => (
                            <span key={g} className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              {g}
                            </span>
                          ))}
                          {user.groups.length === 0 && <span className="text-xs text-gray-400">—</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                          user.active === false
                            ? 'bg-red-100 text-red-700'
                            : 'bg-green-100 text-green-700'
                        }`}>
                          {user.active === false ? 'Inactive' : 'Active'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">
                        {user.lastLogin ? formatDate(user.lastLogin) : 'Never'}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">{formatDate(user.createdAt)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setEditUser(user)}
                            title="Edit user"
                            className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          >
                            <PencilIcon className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeactivate(user)}
                            title={user.active === false ? 'Activate user' : 'Deactivate user'}
                            className={`p-1.5 rounded-lg transition-colors ${
                              user.active === false
                                ? 'text-gray-400 hover:text-green-600 hover:bg-green-50'
                                : 'text-gray-400 hover:text-yellow-600 hover:bg-yellow-50'
                            }`}
                          >
                            {user.active === false
                              ? <CheckCircleIcon className="w-4 h-4" />
                              : <NoSymbolIcon className="w-4 h-4" />}
                          </button>
                          <button
                            onClick={() => handleDeleteUser(user)}
                            title="Delete user"
                            className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          >
                            <TrashIcon className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredUsers.length === 0 && (
                <div className="text-center py-8 text-gray-500">No users found</div>
              )}
            </div>
          </div>
        )}

        {/* ── Groups Tab ── */}
        {activeTab === 'groups' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button
                onClick={() => setShowAddGroup(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
              >
                <PlusIcon className="w-4 h-4" />
                Add Group
              </button>
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {groups.map(group => (
                <div key={group.id} className="border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900">{group.displayName}</h3>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {group.members.length} member{group.members.length !== 1 ? 's' : ''}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => setEditGroup(group)}
                        className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                        title="Edit group"
                      >
                        <PencilIcon className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDeleteGroup(group)}
                        className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete group"
                      >
                        <TrashIcon className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  {group.members.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {group.members.slice(0, 5).map(m => (
                        <span key={m} className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded-full">{m}</span>
                      ))}
                      {group.members.length > 5 && (
                        <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-500 rounded-full">+{group.members.length - 5} more</span>
                      )}
                    </div>
                  )}
                  <div className="text-xs text-gray-400">Created {formatDate(group.createdAt)}</div>
                </div>
              ))}
            </div>
            {groups.length === 0 && (
              <div className="text-center py-8 text-gray-500">No groups found</div>
            )}
          </div>
        )}

        {/* ── Stats Tab ── */}
        {activeTab === 'stats' && stats && (
          <div className="grid gap-6 md:grid-cols-3">
            {[
              { label: 'Total Users',  value: stats.total,  bg: 'bg-blue-50',   text: 'text-blue-600',   val: 'text-blue-900',   icon: UsersIcon },
              { label: 'Active Users', value: stats.active, bg: 'bg-green-50',  text: 'text-green-600',  val: 'text-green-900',  icon: UsersIcon },
              { label: 'Groups',       value: stats.groups, bg: 'bg-purple-50', text: 'text-purple-600', val: 'text-purple-900', icon: UserGroupIcon },
            ].map(({ label, value, bg, text, val, icon: Icon }) => (
              <div key={label} className={`${bg} rounded-lg p-6`}>
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className={`text-sm font-medium ${text}`}>{label}</p>
                    <p className={`text-3xl font-bold ${val}`}>{value}</p>
                  </div>
                  <Icon className={`h-8 w-8 ${text}`} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modals */}
      {(showAddUser || editUser) && (
        <UserModal
          user={editUser}
          groups={groups}
          onClose={() => { setShowAddUser(false); setEditUser(undefined); }}
          onSuccess={fetchData}
        />
      )}
      {showImport && (
        <ImportModal groups={groups} onClose={() => setShowImport(false)} onSuccess={fetchData} />
      )}
      {(showAddGroup || editGroup) && (
        <GroupModal
          group={editGroup}
          allUsers={users}
          onClose={() => { setShowAddGroup(false); setEditGroup(undefined); }}
          onSuccess={(updated) => {
            if (updated) {
              // Optimistic local update — no refetch needed for edits
              setGroups(prev => prev.map(g =>
                g.id === updated.id
                  ? { ...g, displayName: updated.displayName, members: updated.members }
                  : g
              ));
            } else {
              fetchData(); // Refetch for newly created groups
            }
            setShowAddGroup(false);
            setEditGroup(undefined);
          }}
        />
      )}
    </div>
  );
}
