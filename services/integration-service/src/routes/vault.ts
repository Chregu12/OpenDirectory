import { Router, Request, Response } from 'express';
import { VaultService } from '../services/vault.service';
import logger from '../lib/logger';

const router = Router();
const vaultService = new VaultService();

// Secret management endpoints (KV v2)
router.get('/secrets', async (req: Request, res: Response) => {
  try {
    const path = (req.query.path as string) || '';
    const secrets = await vaultService.listSecrets(path);
    res.json({ secrets, path, total: secrets.length });
  } catch (error) {
    logger.error('Failed to list Vault secrets:', error);
    res.status(500).json({ error: 'Failed to list secrets' });
  }
});

router.get('/secrets/*', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    const secret = await vaultService.getSecret(path);
    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }
    
    res.json(secret);
  } catch (error) {
    logger.error(`Failed to get secret at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to get secret' });
  }
});

router.put('/secrets/*', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    const { data } = req.body;

    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }
    
    if (!data || typeof data !== 'object') {
      return res.status(400).json({ error: 'Secret data object is required' });
    }

    const success = await vaultService.putSecret(path, data);
    if (success) {
      res.status(201).json({ message: 'Secret created/updated successfully', path });
    } else {
      res.status(500).json({ error: 'Failed to create/update secret' });
    }
  } catch (error) {
    logger.error(`Failed to put secret at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to put secret' });
  }
});

router.delete('/secrets/*', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    const success = await vaultService.deleteSecret(path);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to delete secret' });
    }
  } catch (error) {
    logger.error(`Failed to delete secret at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to delete secret' });
  }
});

// Secret metadata
router.get('/metadata/*', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    const metadata = await vaultService.getSecretMetadata(path);
    if (!metadata) {
      return res.status(404).json({ error: 'Secret metadata not found' });
    }
    
    res.json(metadata);
  } catch (error) {
    logger.error(`Failed to get secret metadata at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to get secret metadata' });
  }
});

router.post('/metadata/*', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    const metadata = req.body;

    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    const success = await vaultService.updateSecretMetadata(path, metadata);
    if (success) {
      res.json({ message: 'Secret metadata updated successfully', path });
    } else {
      res.status(500).json({ error: 'Failed to update secret metadata' });
    }
  } catch (error) {
    logger.error(`Failed to update secret metadata at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to update secret metadata' });
  }
});

// Secret versioning
router.get('/secrets/*/versions/:version', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    const version = parseInt(req.params.version);

    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    if (isNaN(version)) {
      return res.status(400).json({ error: 'Valid version number is required' });
    }

    const secret = await vaultService.getSecretVersion(path, version);
    if (!secret) {
      return res.status(404).json({ error: 'Secret version not found' });
    }
    
    res.json(secret);
  } catch (error) {
    logger.error(`Failed to get secret version ${req.params.version} at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to get secret version' });
  }
});

router.delete('/secrets/*/versions', async (req: Request, res: Response) => {
  try {
    const path = req.params[0];
    const { versions } = req.body;

    if (!path) {
      return res.status(400).json({ error: 'Secret path is required' });
    }

    if (!Array.isArray(versions) || versions.length === 0) {
      return res.status(400).json({ error: 'Array of version numbers is required' });
    }

    const success = await vaultService.deleteSecretVersions(path, versions);
    if (success) {
      res.json({ message: 'Secret versions deleted successfully', path, versions });
    } else {
      res.status(500).json({ error: 'Failed to delete secret versions' });
    }
  } catch (error) {
    logger.error(`Failed to delete secret versions at path ${req.params[0]}:`, error);
    res.status(500).json({ error: 'Failed to delete secret versions' });
  }
});

// Authentication methods
router.get('/auth/userpass/users', async (req: Request, res: Response) => {
  try {
    const users = await vaultService.listUserpassUsers();
    res.json({ users, total: users.length });
  } catch (error) {
    logger.error('Failed to list userpass users:', error);
    res.status(500).json({ error: 'Failed to list userpass users' });
  }
});

router.post('/auth/userpass/users/:username', async (req: Request, res: Response) => {
  try {
    const { username } = req.params;
    const { password, policies } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const success = await vaultService.createUserpassUser(username, password, policies || []);
    if (success) {
      res.status(201).json({ message: 'Userpass user created successfully', username });
    } else {
      res.status(500).json({ error: 'Failed to create userpass user' });
    }
  } catch (error) {
    logger.error(`Failed to create userpass user ${req.params.username}:`, error);
    res.status(500).json({ error: 'Failed to create userpass user' });
  }
});

router.put('/auth/userpass/users/:username', async (req: Request, res: Response) => {
  try {
    const { username } = req.params;
    const updates = req.body;

    const success = await vaultService.updateUserpassUser(username, updates);
    if (success) {
      res.json({ message: 'Userpass user updated successfully', username });
    } else {
      res.status(500).json({ error: 'Failed to update userpass user' });
    }
  } catch (error) {
    logger.error(`Failed to update userpass user ${req.params.username}:`, error);
    res.status(500).json({ error: 'Failed to update userpass user' });
  }
});

router.delete('/auth/userpass/users/:username', async (req: Request, res: Response) => {
  try {
    const { username } = req.params;

    const success = await vaultService.deleteUserpassUser(username);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to delete userpass user' });
    }
  } catch (error) {
    logger.error(`Failed to delete userpass user ${req.params.username}:`, error);
    res.status(500).json({ error: 'Failed to delete userpass user' });
  }
});

// Token operations
router.post('/auth/tokens', async (req: Request, res: Response) => {
  try {
    const options = req.body;
    const token = await vaultService.createToken(options);
    if (token) {
      res.status(201).json(token);
    } else {
      res.status(500).json({ error: 'Failed to create token' });
    }
  } catch (error) {
    logger.error('Failed to create token:', error);
    res.status(500).json({ error: 'Failed to create token' });
  }
});

router.post('/auth/tokens/renew/:token?', async (req: Request, res: Response) => {
  try {
    const token = req.params.token;
    const result = await vaultService.renewToken(token);
    if (result) {
      res.json(result);
    } else {
      res.status(500).json({ error: 'Failed to renew token' });
    }
  } catch (error) {
    logger.error('Failed to renew token:', error);
    res.status(500).json({ error: 'Failed to renew token' });
  }
});

router.delete('/auth/tokens/:token', async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const success = await vaultService.revokeToken(token);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  } catch (error) {
    logger.error(`Failed to revoke token ${req.params.token}:`, error);
    res.status(500).json({ error: 'Failed to revoke token' });
  }
});

router.get('/auth/tokens/lookup/:token?', async (req: Request, res: Response) => {
  try {
    const token = req.params.token;
    const result = await vaultService.lookupToken(token);
    if (result) {
      res.json(result);
    } else {
      res.status(404).json({ error: 'Token not found or lookup failed' });
    }
  } catch (error) {
    logger.error('Failed to lookup token:', error);
    res.status(500).json({ error: 'Failed to lookup token' });
  }
});

// Policy management
router.get('/policies', async (req: Request, res: Response) => {
  try {
    const policies = await vaultService.listPolicies();
    res.json({ policies, total: policies.length });
  } catch (error) {
    logger.error('Failed to list Vault policies:', error);
    res.status(500).json({ error: 'Failed to list policies' });
  }
});

router.get('/policies/:name', async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const policy = await vaultService.getPolicy(name);
    if (!policy) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    res.json(policy);
  } catch (error) {
    logger.error(`Failed to get policy ${req.params.name}:`, error);
    res.status(500).json({ error: 'Failed to get policy' });
  }
});

router.put('/policies/:name', async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const { policy } = req.body;

    if (!policy) {
      return res.status(400).json({ error: 'Policy content is required' });
    }

    const success = await vaultService.putPolicy(name, policy);
    if (success) {
      res.status(201).json({ message: 'Policy created/updated successfully', name });
    } else {
      res.status(500).json({ error: 'Failed to create/update policy' });
    }
  } catch (error) {
    logger.error(`Failed to put policy ${req.params.name}:`, error);
    res.status(500).json({ error: 'Failed to put policy' });
  }
});

router.delete('/policies/:name', async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const success = await vaultService.deletePolicy(name);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to delete policy' });
    }
  } catch (error) {
    logger.error(`Failed to delete policy ${req.params.name}:`, error);
    res.status(500).json({ error: 'Failed to delete policy' });
  }
});

// System information
router.get('/sys/health', async (req: Request, res: Response) => {
  try {
    const health = await vaultService.getHealth();
    if (health) {
      // Return appropriate status based on Vault health
      const status = health.sealed ? 503 : 200;
      res.status(status).json(health);
    } else {
      res.status(503).json({ error: 'Unable to get Vault health status' });
    }
  } catch (error) {
    logger.error('Failed to get Vault health:', error);
    res.status(500).json({ error: 'Failed to get Vault health' });
  }
});

router.get('/sys/seal-status', async (req: Request, res: Response) => {
  try {
    const status = await vaultService.getSealStatus();
    if (status) {
      res.json(status);
    } else {
      res.status(500).json({ error: 'Failed to get seal status' });
    }
  } catch (error) {
    logger.error('Failed to get seal status:', error);
    res.status(500).json({ error: 'Failed to get seal status' });
  }
});

router.get('/sys/leader', async (req: Request, res: Response) => {
  try {
    const leader = await vaultService.getLeaderStatus();
    if (leader) {
      res.json(leader);
    } else {
      res.status(500).json({ error: 'Failed to get leader status' });
    }
  } catch (error) {
    logger.error('Failed to get leader status:', error);
    res.status(500).json({ error: 'Failed to get leader status' });
  }
});

router.get('/sys/mounts', async (req: Request, res: Response) => {
  try {
    const mounts = await vaultService.getMounts();
    if (mounts) {
      res.json(mounts);
    } else {
      res.status(500).json({ error: 'Failed to get mounts' });
    }
  } catch (error) {
    logger.error('Failed to get mounts:', error);
    res.status(500).json({ error: 'Failed to get mounts' });
  }
});

router.get('/sys/auth', async (req: Request, res: Response) => {
  try {
    const authMethods = await vaultService.getAuthMethods();
    if (authMethods) {
      res.json(authMethods);
    } else {
      res.status(500).json({ error: 'Failed to get auth methods' });
    }
  } catch (error) {
    logger.error('Failed to get auth methods:', error);
    res.status(500).json({ error: 'Failed to get auth methods' });
  }
});

// Service status
router.get('/status', async (req: Request, res: Response) => {
  try {
    const status = await vaultService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Failed to get Vault service status:', error);
    res.status(500).json({ error: 'Failed to get service status' });
  }
});

// OpenDirectory-specific endpoints
router.get('/opendirectory/secrets', async (req: Request, res: Response) => {
  try {
    const secrets = await vaultService.getOpenDirectorySecrets();
    res.json({ secrets, total: secrets.length });
  } catch (error) {
    logger.error('Failed to get OpenDirectory secrets:', error);
    res.status(500).json({ error: 'Failed to get OpenDirectory secrets' });
  }
});

router.get('/opendirectory/services/:service/credentials', async (req: Request, res: Response) => {
  try {
    const { service } = req.params;
    const credentials = await vaultService.getServiceCredentials(service);
    if (!credentials) {
      return res.status(404).json({ error: 'Service credentials not found' });
    }
    res.json({ service, credentials });
  } catch (error) {
    logger.error(`Failed to get credentials for service ${req.params.service}:`, error);
    res.status(500).json({ error: 'Failed to get service credentials' });
  }
});

router.put('/opendirectory/services/:service/credentials', async (req: Request, res: Response) => {
  try {
    const { service } = req.params;
    const { credentials } = req.body;

    if (!credentials || typeof credentials !== 'object') {
      return res.status(400).json({ error: 'Credentials object is required' });
    }

    const success = await vaultService.storeServiceCredentials(service, credentials);
    if (success) {
      res.status(201).json({ message: 'Service credentials stored successfully', service });
    } else {
      res.status(500).json({ error: 'Failed to store service credentials' });
    }
  } catch (error) {
    logger.error(`Failed to store credentials for service ${req.params.service}:`, error);
    res.status(500).json({ error: 'Failed to store service credentials' });
  }
});

router.get('/opendirectory/api-keys/:keyName', async (req: Request, res: Response) => {
  try {
    const { keyName } = req.params;
    const apiKey = await vaultService.getAPIKey(keyName);
    if (!apiKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    res.json({ keyName, apiKey });
  } catch (error) {
    logger.error(`Failed to get API key ${req.params.keyName}:`, error);
    res.status(500).json({ error: 'Failed to get API key' });
  }
});

router.put('/opendirectory/api-keys/:keyName', async (req: Request, res: Response) => {
  try {
    const { keyName } = req.params;
    const { apiKey, metadata } = req.body;

    if (!apiKey) {
      return res.status(400).json({ error: 'API key value is required' });
    }

    const success = await vaultService.storeAPIKey(keyName, apiKey, metadata || {});
    if (success) {
      res.status(201).json({ message: 'API key stored successfully', keyName });
    } else {
      res.status(500).json({ error: 'Failed to store API key' });
    }
  } catch (error) {
    logger.error(`Failed to store API key ${req.params.keyName}:`, error);
    res.status(500).json({ error: 'Failed to store API key' });
  }
});

export default router;