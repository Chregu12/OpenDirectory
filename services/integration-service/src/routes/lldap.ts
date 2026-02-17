import { Router, Request, Response } from 'express';
import { LLDAPService } from '../services/lldap.service';
import logger from '../lib/logger';

const router = Router();
const lldapService = new LLDAPService();

// Users endpoints
router.get('/users', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;
    const users = await lldapService.getUsers(limit, offset);
    res.json({ users, total: users.length });
  } catch (error) {
    logger.error('Failed to fetch users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

router.get('/users/search', async (req: Request, res: Response) => {
  try {
    const query = req.query.q as string;
    if (!query) {
      return res.status(400).json({ error: 'Query parameter "q" is required' });
    }
    const users = await lldapService.searchUsers(query);
    res.json({ users, total: users.length });
  } catch (error) {
    logger.error('Failed to search users:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

router.get('/users/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const user = await lldapService.getUser(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    logger.error(`Failed to fetch user ${req.params.userId}:`, error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

router.post('/users', async (req: Request, res: Response) => {
  try {
    const userData = req.body;
    const user = await lldapService.createUser(userData);
    res.status(201).json(user);
  } catch (error) {
    logger.error('Failed to create user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

router.put('/users/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const userData = req.body;
    const user = await lldapService.updateUser(userId, userData);
    res.json(user);
  } catch (error) {
    logger.error(`Failed to update user ${req.params.userId}:`, error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

router.delete('/users/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const success = await lldapService.deleteUser(userId);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to delete user' });
    }
  } catch (error) {
    logger.error(`Failed to delete user ${req.params.userId}:`, error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

router.get('/users/:userId/groups', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const groups = await lldapService.getUserGroups(userId);
    res.json({ groups, total: groups.length });
  } catch (error) {
    logger.error(`Failed to fetch groups for user ${req.params.userId}:`, error);
    res.status(500).json({ error: 'Failed to fetch user groups' });
  }
});

// Groups endpoints
router.get('/groups', async (req: Request, res: Response) => {
  try {
    const groups = await lldapService.getGroups();
    res.json({ groups, total: groups.length });
  } catch (error) {
    logger.error('Failed to fetch groups:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

router.get('/groups/:groupId', async (req: Request, res: Response) => {
  try {
    const { groupId } = req.params;
    const group = await lldapService.getGroup(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    res.json(group);
  } catch (error) {
    logger.error(`Failed to fetch group ${req.params.groupId}:`, error);
    res.status(500).json({ error: 'Failed to fetch group' });
  }
});

// Group membership management
router.post('/groups/:groupId/members', async (req: Request, res: Response) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const success = await lldapService.addUserToGroup(userId, groupId);
    if (success) {
      res.status(200).json({ message: 'User added to group successfully' });
    } else {
      res.status(500).json({ error: 'Failed to add user to group' });
    }
  } catch (error) {
    logger.error(`Failed to add user to group ${req.params.groupId}:`, error);
    res.status(500).json({ error: 'Failed to add user to group' });
  }
});

router.delete('/groups/:groupId/members/:userId', async (req: Request, res: Response) => {
  try {
    const { groupId, userId } = req.params;
    const success = await lldapService.removeUserFromGroup(userId, groupId);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to remove user from group' });
    }
  } catch (error) {
    logger.error(`Failed to remove user from group ${req.params.groupId}:`, error);
    res.status(500).json({ error: 'Failed to remove user from group' });
  }
});

// Authentication endpoints
router.post('/auth/validate', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const isValid = await lldapService.validateLDAPCredentials(username, password);
    res.json({ valid: isValid });
  } catch (error) {
    logger.error('Failed to validate credentials:', error);
    res.status(500).json({ error: 'Failed to validate credentials' });
  }
});

// LDAP schema
router.get('/schema', async (req: Request, res: Response) => {
  try {
    const schema = await lldapService.getLDAPSchema();
    if (schema) {
      res.json(schema);
    } else {
      res.status(404).json({ error: 'Schema not available' });
    }
  } catch (error) {
    logger.error('Failed to fetch LDAP schema:', error);
    res.status(500).json({ error: 'Failed to fetch LDAP schema' });
  }
});

// Service status
router.get('/status', async (req: Request, res: Response) => {
  try {
    const status = await lldapService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Failed to get LLDAP service status:', error);
    res.status(500).json({ error: 'Failed to get service status' });
  }
});

// Statistics endpoint
router.get('/stats', async (req: Request, res: Response) => {
  try {
    const users = await lldapService.getUsers(1000, 0); // Get up to 1000 users for stats
    const groups = await lldapService.getGroups();
    
    const userStats = {
      total: users.length,
      active: users.filter(u => u.lastLogin && new Date(u.lastLogin) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)).length,
      groups: groups.length,
    };

    res.json({
      statistics: userStats,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Failed to fetch LLDAP statistics:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

export default router;