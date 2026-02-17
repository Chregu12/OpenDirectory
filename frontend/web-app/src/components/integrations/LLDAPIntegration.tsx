'use client';

import React, { useState, useEffect } from 'react';
import { UserGroupIcon, UsersIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { lldapApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

interface User {
  id: string;
  email: string;
  displayName: string;
  firstName: string;
  lastName: string;
  groups: string[];
  createdAt: string;
  lastLogin?: string;
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

export default function LLDAPIntegration() {
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'users' | 'groups' | 'stats'>('users');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [usersResponse, groupsResponse, statsResponse] = await Promise.all([
        lldapApi.getUsers({ limit: 100 }),
        lldapApi.getGroups(),
        lldapApi.getStats(),
      ]);

      setUsers(usersResponse.data.users || []);
      setGroups(groupsResponse.data.groups || []);
      setStats(statsResponse.data.statistics || null);
    } catch (error) {
      toast.error(`Failed to fetch LLDAP data: ${formatError(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (query: string) => {
    if (!query.trim()) {
      fetchData();
      return;
    }

    try {
      const response = await lldapApi.searchUsers(query);
      setUsers(response.data.users || []);
    } catch (error) {
      toast.error(`Search failed: ${formatError(error)}`);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-2">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded w-5/6"></div>
            <div className="h-4 bg-gray-200 rounded w-4/6"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <UserGroupIcon className="h-6 w-6 text-blue-600" />
              <h2 className="text-lg font-medium text-gray-900">User Directory (LLDAP)</h2>
            </div>
            <div className="flex items-center space-x-4">
              {stats && (
                <div className="text-sm text-gray-500">
                  {stats.total} users • {stats.groups} groups
                </div>
              )}
            </div>
          </div>
        </div>
        
        <nav className="flex space-x-8 px-6" aria-label="Tabs">
          {[
            { key: 'users' as const, label: 'Users', icon: UsersIcon },
            { key: 'groups' as const, label: 'Groups', icon: UserGroupIcon },
            { key: 'stats' as const, label: 'Statistics', icon: UsersIcon },
          ].map((tab) => (
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
        {activeTab === 'users' && (
          <div className="space-y-4">
            {/* Search */}
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch(searchQuery)}
                placeholder="Search users..."
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Users List */}
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <table className="min-w-full divide-y divide-gray-300">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      User
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Groups
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Last Login
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {users.map((user) => (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {user.displayName}
                          </div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex flex-wrap gap-1">
                          {user.groups.map((group) => (
                            <span
                              key={group}
                              className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                            >
                              {group}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {user.lastLogin ? formatDate(user.lastLogin) : 'Never'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatDate(user.createdAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {users.length === 0 && (
                <div className="text-center py-8 text-gray-500">No users found</div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'groups' && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {groups.map((group) => (
                <div key={group.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-medium text-gray-900">
                      {group.displayName}
                    </h3>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                      {group.members.length} members
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">
                    Created {formatDate(group.createdAt)}
                  </div>
                </div>
              ))}
            </div>
            {groups.length === 0 && (
              <div className="text-center py-8 text-gray-500">No groups found</div>
            )}
          </div>
        )}

        {activeTab === 'stats' && stats && (
          <div className="grid gap-6 md:grid-cols-3">
            <div className="bg-blue-50 rounded-lg p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-blue-600">Total Users</p>
                  <p className="text-3xl font-bold text-blue-900">{stats.total}</p>
                </div>
                <UsersIcon className="h-8 w-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-green-50 rounded-lg p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-green-600">Active Users</p>
                  <p className="text-3xl font-bold text-green-900">{stats.active}</p>
                </div>
                <UsersIcon className="h-8 w-8 text-green-600" />
              </div>
            </div>
            
            <div className="bg-purple-50 rounded-lg p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-purple-600">Groups</p>
                  <p className="text-3xl font-bold text-purple-900">{stats.groups}</p>
                </div>
                <UserGroupIcon className="h-8 w-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}