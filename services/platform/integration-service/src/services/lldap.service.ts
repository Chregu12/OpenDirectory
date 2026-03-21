import axios from 'axios';
import { LLDAPUser, LLDAPGroup, ServiceStatus } from '../types';
import logger from '../lib/logger';

const LLDAP_URL  = process.env.LLDAP_URL            || 'http://lldap:17170';
const LLDAP_USER = process.env.LLDAP_ADMIN_USER     || 'admin';
const LLDAP_PASS = process.env.LLDAP_ADMIN_PASSWORD || 'changeme';

export class LLDAPService {
  private token: string | null = null;
  private tokenExpiry = 0;

  // ── Auth ──────────────────────────────────────────────────────────────────
  private async getToken(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiry) return this.token;
    const res = await axios.post(`${LLDAP_URL}/auth/simple/login`, {
      username: LLDAP_USER, password: LLDAP_PASS,
    });
    this.token = res.data.token as string;
    this.tokenExpiry = Date.now() + 23 * 60 * 60 * 1000;
    return this.token;
  }

  private async gql<T = any>(query: string, variables?: Record<string, any>): Promise<T> {
    const token = await this.getToken();
    const res = await axios.post(`${LLDAP_URL}/api/graphql`,
      { query, variables },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
    );
    if (res.data.errors?.length) throw new Error(res.data.errors[0].message);
    return res.data.data as T;
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  async getUsers(_limit = 50, _offset = 0): Promise<LLDAPUser[]> {
    try {
      const data = await this.gql<{ users: any[] }>(`{
        users {
          id displayName email creationDate
          groups { id displayName }
        }
      }`);
      return (data.users || []).map(this.mapUser);
    } catch (error) {
      logger.error('Failed to fetch users from LLDAP:', error);
      throw new Error('Failed to fetch users from LLDAP');
    }
  }

  async getUser(userId: string): Promise<LLDAPUser | null> {
    try {
      const data = await this.gql<{ user: any }>(`
        query GetUser($id: String!) {
          user(id: $id) { id displayName email creationDate groups { id displayName } }
        }`, { id: userId });
      return data.user ? this.mapUser(data.user) : null;
    } catch { return null; }
  }

  async searchUsers(query: string): Promise<LLDAPUser[]> {
    const all = await this.getUsers().catch(() => []);
    const q = query.toLowerCase();
    return all.filter(u =>
      u.id?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.displayName?.toLowerCase().includes(q)
    );
  }

  async createUser(userData: any): Promise<LLDAPUser> {
    const data = await this.gql<{ createUser: any }>(`
      mutation CreateUser($user: CreateUserInput!) {
        createUser(user: $user) { id displayName email creationDate groups { id displayName } }
      }`, {
      user: {
        id:          userData.username || userData.id,
        displayName: userData.name || userData.displayName || userData.username,
        email:       userData.email || `${userData.username}@opendirectory.local`,
        ...(userData.password ? { password: userData.password } : {}),
      }
    });
    if (userData.groups?.length) {
      for (const gId of userData.groups) {
        await this.addUserToGroup(data.createUser.id, gId).catch(() => {});
      }
    }
    return this.mapUser(data.createUser);
  }

  async updateUser(userId: string, userData: any): Promise<LLDAPUser> {
    await this.gql(`
      mutation UpdateUser($user: UpdateUserInput!) { updateUser(user: $user) { ok } }`, {
      user: {
        id: userId,
        ...(userData.name || userData.displayName ? { displayName: userData.name || userData.displayName } : {}),
        ...(userData.email ? { email: userData.email } : {}),
      }
    });
    return (await this.getUser(userId))!;
  }

  async deleteUser(userId: string): Promise<void> {
    await this.gql(`
      mutation DeleteUser($userId: String!) { deleteUser(userId: $userId) { ok } }`, { userId });
  }

  async changePassword(userId: string, password: string): Promise<void> {
    await this.gql(`
      mutation ChangePassword($userId: String!, $password: String!) {
        updateUser(user: { id: $userId, password: $password }) { ok }
      }`, { userId, password });
  }

  async getUserGroups(userId: string): Promise<LLDAPGroup[]> {
    const user = await this.getUser(userId);
    if (!user) return [];
    const groups = await this.getGroups().catch(() => []);
    return groups.filter(g => (user.groups as string[]).includes(g.id));
  }

  async addUserToGroup(userId: string, groupId: string | number): Promise<void> {
    await this.gql(`
      mutation AddToGroup($userId: String!, $groupId: Int!) {
        addUserToGroup(userId: $userId, groupId: $groupId) { ok }
      }`, { userId, groupId: Number(groupId) });
  }

  async removeUserFromGroup(userId: string, groupId: string | number): Promise<void> {
    await this.gql(`
      mutation RemoveFromGroup($userId: String!, $groupId: Int!) {
        removeUserFromGroup(userId: $userId, groupId: $groupId) { ok }
      }`, { userId, groupId: Number(groupId) });
  }

  async validateLDAPCredentials(username: string, password: string): Promise<boolean> {
    try {
      await axios.post(`${LLDAP_URL}/auth/simple/login`, { username, password });
      return true;
    } catch { return false; }
  }

  async getLDAPSchema(): Promise<Record<string, any> | null> {
    try {
      const data = await this.gql<{ schema: any }>(`{ schema { userSchema { attributes { name attributeType } } } }`);
      return data.schema || null;
    } catch { return null; }
  }

  // ── Groups ────────────────────────────────────────────────────────────────
  async getGroups(): Promise<LLDAPGroup[]> {
    try {
      const data = await this.gql<{ groups: any[] }>(`{
        groups { id displayName users { id } }
      }`);
      return (data.groups || []).map(g => ({
        id:          String(g.id),
        displayName: g.displayName,
        members:     (g.users || []).map((u: any) => u.id),
        createdAt:   new Date().toISOString(),
      }));
    } catch (error) {
      logger.error('Failed to fetch groups from LLDAP:', error);
      throw new Error('Failed to fetch groups');
    }
  }

  async getGroup(groupId: string): Promise<LLDAPGroup | null> {
    try {
      const data = await this.gql<{ group: any }>(`
        query GetGroup($id: Int!) {
          group(id: $id) { id displayName users { id } }
        }`, { id: Number(groupId) });
      const g = data.group;
      return g ? { id: String(g.id), displayName: g.displayName, members: (g.users || []).map((u: any) => u.id), createdAt: new Date().toISOString() } : null;
    } catch { return null; }
  }

  async createGroup(name: string): Promise<LLDAPGroup> {
    const data = await this.gql<{ createGroup: any }>(`
      mutation CreateGroup($name: String!) { createGroup(name: $name) { id displayName } }`, { name });
    return { id: String(data.createGroup.id), displayName: data.createGroup.displayName, members: [], createdAt: new Date().toISOString() };
  }

  async deleteGroup(groupId: string): Promise<void> {
    await this.gql(`
      mutation DeleteGroup($groupId: Int!) { deleteGroup(groupId: $groupId) { ok } }`, { groupId: Number(groupId) });
  }

  // ── Health ────────────────────────────────────────────────────────────────
  async getServiceStatus(): Promise<ServiceStatus> {
    try {
      await this.getToken();
      return { name: 'LLDAP', status: 'healthy', lastCheck: new Date().toISOString() };
    } catch {
      return { name: 'LLDAP', status: 'unhealthy', lastCheck: new Date().toISOString() };
    }
  }

  // ── Helper ────────────────────────────────────────────────────────────────
  private mapUser(u: any): LLDAPUser {
    const [firstName = '', ...lastParts] = (u.displayName || u.id || '').split(' ');
    return {
      id:          u.id,
      email:       u.email || '',
      displayName: u.displayName || u.id,
      firstName,
      lastName:    lastParts.join(' '),
      groups:      (u.groups || []).map((g: any) => String(g.id)),
      createdAt:   u.creationDate || new Date().toISOString(),
      lastLogin:   u.lastLogin,
    };
  }
}
