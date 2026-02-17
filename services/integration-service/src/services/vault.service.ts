import { HttpClient } from '../lib/http-client';
import { SERVICES } from '../config/services';
import { VaultSecret, ServiceStatus } from '../types';
import logger from '../lib/logger';

export class VaultService {
  private client: HttpClient;

  constructor() {
    this.client = new HttpClient(SERVICES.vault);
  }

  // KV Secrets Engine v2 operations
  async getSecret(path: string): Promise<VaultSecret | null> {
    try {
      const response = await this.client.get(`/v1/secret/data/${path}`);
      return {
        path,
        data: response.data?.data || {},
        metadata: response.data?.metadata || {},
      };
    } catch (error) {
      logger.error(`Failed to get secret at path ${path}:`, error);
      return null;
    }
  }

  async putSecret(path: string, data: Record<string, any>): Promise<boolean> {
    try {
      await this.client.post(`/v1/secret/data/${path}`, { data });
      return true;
    } catch (error) {
      logger.error(`Failed to put secret at path ${path}:`, error);
      return false;
    }
  }

  async deleteSecret(path: string): Promise<boolean> {
    try {
      await this.client.delete(`/v1/secret/data/${path}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete secret at path ${path}:`, error);
      return false;
    }
  }

  async listSecrets(path: string): Promise<string[]> {
    try {
      const response = await this.client.get(`/v1/secret/metadata/${path}?list=true`);
      return response.data?.keys || [];
    } catch (error) {
      logger.error(`Failed to list secrets at path ${path}:`, error);
      return [];
    }
  }

  async getSecretMetadata(path: string): Promise<any> {
    try {
      const response = await this.client.get(`/v1/secret/metadata/${path}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to get secret metadata at path ${path}:`, error);
      return null;
    }
  }

  async updateSecretMetadata(path: string, metadata: Record<string, any>): Promise<boolean> {
    try {
      await this.client.post(`/v1/secret/metadata/${path}`, metadata);
      return true;
    } catch (error) {
      logger.error(`Failed to update secret metadata at path ${path}:`, error);
      return false;
    }
  }

  // Secret versioning
  async getSecretVersion(path: string, version: number): Promise<VaultSecret | null> {
    try {
      const response = await this.client.get(`/v1/secret/data/${path}?version=${version}`);
      return {
        path,
        data: response.data?.data || {},
        metadata: response.data?.metadata || {},
      };
    } catch (error) {
      logger.error(`Failed to get secret version ${version} at path ${path}:`, error);
      return null;
    }
  }

  async deleteSecretVersions(path: string, versions: number[]): Promise<boolean> {
    try {
      await this.client.post(`/v1/secret/delete/${path}`, { versions });
      return true;
    } catch (error) {
      logger.error(`Failed to delete secret versions at path ${path}:`, error);
      return false;
    }
  }

  async undeleteSecretVersions(path: string, versions: number[]): Promise<boolean> {
    try {
      await this.client.post(`/v1/secret/undelete/${path}`, { versions });
      return true;
    } catch (error) {
      logger.error(`Failed to undelete secret versions at path ${path}:`, error);
      return false;
    }
  }

  async destroySecretVersions(path: string, versions: number[]): Promise<boolean> {
    try {
      await this.client.post(`/v1/secret/destroy/${path}`, { versions });
      return true;
    } catch (error) {
      logger.error(`Failed to destroy secret versions at path ${path}:`, error);
      return false;
    }
  }

  // Authentication methods
  async createUserpassUser(username: string, password: string, policies: string[] = []): Promise<boolean> {
    try {
      await this.client.post(`/v1/auth/userpass/users/${username}`, {
        password,
        policies,
      });
      return true;
    } catch (error) {
      logger.error(`Failed to create userpass user ${username}:`, error);
      return false;
    }
  }

  async updateUserpassUser(username: string, updates: any): Promise<boolean> {
    try {
      await this.client.post(`/v1/auth/userpass/users/${username}`, updates);
      return true;
    } catch (error) {
      logger.error(`Failed to update userpass user ${username}:`, error);
      return false;
    }
  }

  async deleteUserpassUser(username: string): Promise<boolean> {
    try {
      await this.client.delete(`/v1/auth/userpass/users/${username}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete userpass user ${username}:`, error);
      return false;
    }
  }

  async listUserpassUsers(): Promise<string[]> {
    try {
      const response = await this.client.get('/v1/auth/userpass/users?list=true');
      return response.data?.keys || [];
    } catch (error) {
      logger.error('Failed to list userpass users:', error);
      return [];
    }
  }

  // Token operations
  async createToken(options: any = {}): Promise<any> {
    try {
      const response = await this.client.post('/v1/auth/token/create', options);
      return response.auth;
    } catch (error) {
      logger.error('Failed to create token:', error);
      return null;
    }
  }

  async renewToken(token?: string): Promise<any> {
    try {
      const endpoint = token ? `/v1/auth/token/renew/${token}` : '/v1/auth/token/renew-self';
      const response = await this.client.post(endpoint);
      return response.auth;
    } catch (error) {
      logger.error('Failed to renew token:', error);
      return null;
    }
  }

  async revokeToken(token: string): Promise<boolean> {
    try {
      await this.client.post(`/v1/auth/token/revoke/${token}`);
      return true;
    } catch (error) {
      logger.error(`Failed to revoke token ${token}:`, error);
      return false;
    }
  }

  async lookupToken(token?: string): Promise<any> {
    try {
      const endpoint = token ? `/v1/auth/token/lookup/${token}` : '/v1/auth/token/lookup-self';
      const response = await this.client.get(endpoint);
      return response.data;
    } catch (error) {
      logger.error('Failed to lookup token:', error);
      return null;
    }
  }

  // Policies
  async getPolicy(name: string): Promise<any> {
    try {
      const response = await this.client.get(`/v1/sys/policies/acl/${name}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to get policy ${name}:`, error);
      return null;
    }
  }

  async putPolicy(name: string, policy: string): Promise<boolean> {
    try {
      await this.client.put(`/v1/sys/policies/acl/${name}`, { policy });
      return true;
    } catch (error) {
      logger.error(`Failed to put policy ${name}:`, error);
      return false;
    }
  }

  async deletePolicy(name: string): Promise<boolean> {
    try {
      await this.client.delete(`/v1/sys/policies/acl/${name}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete policy ${name}:`, error);
      return false;
    }
  }

  async listPolicies(): Promise<string[]> {
    try {
      const response = await this.client.get('/v1/sys/policies/acl?list=true');
      return response.data?.keys || [];
    } catch (error) {
      logger.error('Failed to list policies:', error);
      return [];
    }
  }

  // System operations
  async getHealth(): Promise<any> {
    try {
      const response = await this.client.get('/v1/sys/health');
      return response;
    } catch (error) {
      // Health endpoint returns 503 for standby, 429 for perf standby
      if (error.response && [503, 429].includes(error.response.status)) {
        return error.response.data;
      }
      logger.error('Failed to get Vault health:', error);
      return null;
    }
  }

  async getSealStatus(): Promise<any> {
    try {
      const response = await this.client.get('/v1/sys/seal-status');
      return response;
    } catch (error) {
      logger.error('Failed to get seal status:', error);
      return null;
    }
  }

  async getLeaderStatus(): Promise<any> {
    try {
      const response = await this.client.get('/v1/sys/leader');
      return response;
    } catch (error) {
      logger.error('Failed to get leader status:', error);
      return null;
    }
  }

  async getMounts(): Promise<any> {
    try {
      const response = await this.client.get('/v1/sys/mounts');
      return response.data;
    } catch (error) {
      logger.error('Failed to get mounts:', error);
      return null;
    }
  }

  async getAuthMethods(): Promise<any> {
    try {
      const response = await this.client.get('/v1/sys/auth');
      return response.data;
    } catch (error) {
      logger.error('Failed to get auth methods:', error);
      return null;
    }
  }

  // Service status and health check
  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    
    try {
      const health = await this.getHealth();
      
      if (health) {
        const sealStatus = await this.getSealStatus();
        const leaderStatus = await this.getLeaderStatus();
        
        return {
          name: SERVICES.vault.name,
          status: health.initialized && !health.sealed ? 'healthy' : 'unhealthy',
          lastCheck,
          version: health.version,
          details: {
            initialized: health.initialized,
            sealed: health.sealed,
            standby: health.standby,
            performance_standby: health.performance_standby,
            replication_performance_mode: health.replication_performance_mode,
            replication_dr_mode: health.replication_dr_mode,
            server_time_utc: health.server_time_utc,
            ha_enabled: leaderStatus?.ha_enabled,
            is_leader: leaderStatus?.is_self,
          },
        };
      }
      
      return {
        name: SERVICES.vault.name,
        status: 'unknown',
        lastCheck,
      };
    } catch (error) {
      return {
        name: SERVICES.vault.name,
        status: 'unknown',
        lastCheck,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      };
    }
  }

  // OpenDirectory-specific secret management
  async getOpenDirectorySecrets(): Promise<VaultSecret[]> {
    try {
      const secretPaths = await this.listSecrets('opendirectory');
      const secrets: VaultSecret[] = [];
      
      for (const path of secretPaths) {
        const secret = await this.getSecret(`opendirectory/${path}`);
        if (secret) {
          secrets.push(secret);
        }
      }
      
      return secrets;
    } catch (error) {
      logger.error('Failed to get OpenDirectory secrets:', error);
      return [];
    }
  }

  async storeServiceCredentials(service: string, credentials: Record<string, string>): Promise<boolean> {
    return this.putSecret(`opendirectory/services/${service}`, credentials);
  }

  async getServiceCredentials(service: string): Promise<Record<string, string> | null> {
    const secret = await this.getSecret(`opendirectory/services/${service}`);
    return secret?.data || null;
  }

  async storeAPIKey(keyName: string, keyValue: string, metadata: Record<string, any> = {}): Promise<boolean> {
    const secretData = {
      key: keyValue,
      created: new Date().toISOString(),
      ...metadata,
    };
    
    return this.putSecret(`opendirectory/api-keys/${keyName}`, secretData);
  }

  async getAPIKey(keyName: string): Promise<string | null> {
    const secret = await this.getSecret(`opendirectory/api-keys/${keyName}`);
    return secret?.data?.key || null;
  }
}