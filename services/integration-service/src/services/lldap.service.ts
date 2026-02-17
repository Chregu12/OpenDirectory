import { HttpClient } from '../lib/http-client';
import { SERVICES } from '../config/services';
import { LLDAPUser, LLDAPGroup, ServiceStatus } from '../types';
import logger from '../lib/logger';

export class LLDAPService {
  private client: HttpClient;

  constructor() {
    this.client = new HttpClient(SERVICES.lldap);
  }

  async getUsers(limit = 50, offset = 0): Promise<LLDAPUser[]> {
    try {
      const response = await this.client.get<{ users: LLDAPUser[] }>(
        `/api/users?limit=${limit}&offset=${offset}`
      );
      return response.users || [];
    } catch (error) {
      logger.error('Failed to fetch users from LLDAP:', error);
      throw new Error('Failed to fetch users from LLDAP');
    }
  }

  async getUser(userId: string): Promise<LLDAPUser | null> {
    try {
      const user = await this.client.get<LLDAPUser>(`/api/users/${userId}`);
      return user;
    } catch (error) {
      logger.error(`Failed to fetch user ${userId} from LLDAP:`, error);
      return null;
    }
  }

  async searchUsers(query: string): Promise<LLDAPUser[]> {
    try {
      const response = await this.client.get<{ users: LLDAPUser[] }>(
        `/api/users/search?q=${encodeURIComponent(query)}`
      );
      return response.users || [];
    } catch (error) {
      logger.error('Failed to search users in LLDAP:', error);
      return [];
    }
  }

  async getGroups(): Promise<LLDAPGroup[]> {
    try {
      const response = await this.client.get<{ groups: LLDAPGroup[] }>('/api/groups');
      return response.groups || [];
    } catch (error) {
      logger.error('Failed to fetch groups from LLDAP:', error);
      throw new Error('Failed to fetch groups from LLDAP');
    }
  }

  async getGroup(groupId: string): Promise<LLDAPGroup | null> {
    try {
      const group = await this.client.get<LLDAPGroup>(`/api/groups/${groupId}`);
      return group;
    } catch (error) {
      logger.error(`Failed to fetch group ${groupId} from LLDAP:`, error);
      return null;
    }
  }

  async getUserGroups(userId: string): Promise<LLDAPGroup[]> {
    try {
      const response = await this.client.get<{ groups: LLDAPGroup[] }>(
        `/api/users/${userId}/groups`
      );
      return response.groups || [];
    } catch (error) {
      logger.error(`Failed to fetch groups for user ${userId}:`, error);
      return [];
    }
  }

  async createUser(userData: Partial<LLDAPUser>): Promise<LLDAPUser> {
    try {
      const user = await this.client.post<LLDAPUser>('/api/users', userData);
      return user;
    } catch (error) {
      logger.error('Failed to create user in LLDAP:', error);
      throw new Error('Failed to create user in LLDAP');
    }
  }

  async updateUser(userId: string, userData: Partial<LLDAPUser>): Promise<LLDAPUser> {
    try {
      const user = await this.client.put<LLDAPUser>(`/api/users/${userId}`, userData);
      return user;
    } catch (error) {
      logger.error(`Failed to update user ${userId} in LLDAP:`, error);
      throw new Error('Failed to update user in LLDAP');
    }
  }

  async deleteUser(userId: string): Promise<boolean> {
    try {
      await this.client.delete(`/api/users/${userId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete user ${userId} from LLDAP:`, error);
      return false;
    }
  }

  async addUserToGroup(userId: string, groupId: string): Promise<boolean> {
    try {
      await this.client.post(`/api/groups/${groupId}/members`, { userId });
      return true;
    } catch (error) {
      logger.error(`Failed to add user ${userId} to group ${groupId}:`, error);
      return false;
    }
  }

  async removeUserFromGroup(userId: string, groupId: string): Promise<boolean> {
    try {
      await this.client.delete(`/api/groups/${groupId}/members/${userId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to remove user ${userId} from group ${groupId}:`, error);
      return false;
    }
  }

  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    
    try {
      const isHealthy = await this.client.healthCheck();
      
      if (isHealthy) {
        return {
          name: SERVICES.lldap.name,
          status: 'healthy',
          lastCheck,
        };
      }
      
      return {
        name: SERVICES.lldap.name,
        status: 'unhealthy',
        lastCheck,
      };
    } catch (error) {
      return {
        name: SERVICES.lldap.name,
        status: 'unknown',
        lastCheck,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      };
    }
  }

  // LDAP-specific operations for direct integration
  async validateLDAPCredentials(username: string, password: string): Promise<boolean> {
    try {
      const response = await this.client.post('/api/auth/validate', {
        username,
        password,
      });
      return response.valid || false;
    } catch (error) {
      logger.error('Failed to validate LDAP credentials:', error);
      return false;
    }
  }

  async getLDAPSchema(): Promise<any> {
    try {
      const schema = await this.client.get('/api/schema');
      return schema;
    } catch (error) {
      logger.error('Failed to fetch LDAP schema:', error);
      return null;
    }
  }
}