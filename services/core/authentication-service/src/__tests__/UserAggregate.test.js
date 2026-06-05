'use strict';

const UserAggregate = require('../domain/aggregates/UserAggregate');
const { AuthEvents } = require('../domain/events/AuthEvents');

describe('UserAggregate', () => {
  const baseProps = {
    id: 'user-1',
    username: 'alice',
    email: 'alice@example.com',
    passwordHash: 'hashedpassword',
    roles: ['user'],
  };

  describe('constructor', () => {
    it('sets default roles to ["user"] when not provided', () => {
      const user = new UserAggregate({ id: '1', username: 'u', email: 'u@e.com', passwordHash: 'h' });
      expect(user.roles).toEqual(['user']);
    });

    it('sets mfaEnabled to false by default', () => {
      const user = new UserAggregate(baseProps);
      expect(user.mfaEnabled).toBe(false);
    });

    it('sets locked to false by default', () => {
      const user = new UserAggregate(baseProps);
      expect(user.locked).toBe(false);
    });

    it('sets loginAttempts to 0 by default', () => {
      const user = new UserAggregate(baseProps);
      expect(user.loginAttempts).toBe(0);
    });

    it('initialises with provided props', () => {
      const user = new UserAggregate({ ...baseProps, locked: true, loginAttempts: 3 });
      expect(user.locked).toBe(true);
      expect(user.loginAttempts).toBe(3);
    });
  });

  describe('static create()', () => {
    it('creates a UserAggregate and emits USER_CREATED domain event', () => {
      const user = UserAggregate.create(baseProps);
      expect(user).toBeInstanceOf(UserAggregate);
      const events = user.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(AuthEvents.USER_CREATED);
      expect(events[0].payload.userId).toBe(baseProps.id);
      expect(events[0].payload.username).toBe(baseProps.username);
      expect(events[0].payload.email).toBe(baseProps.email);
    });

    it('uses default role ["user"] in event payload when no roles given', () => {
      const user = UserAggregate.create({ id: '1', username: 'u', email: 'u@e.com', passwordHash: 'h' });
      const [event] = user.getAndClearDomainEvents();
      expect(event.payload.roles).toEqual(['user']);
    });
  });

  describe('recordLoginSuccess()', () => {
    it('resets loginAttempts, unlocks, and emits LOGIN_SUCCESS', () => {
      const user = new UserAggregate({ ...baseProps, loginAttempts: 3, locked: true });
      user.recordLoginSuccess('1.2.3.4');
      expect(user.loginAttempts).toBe(0);
      expect(user.locked).toBe(false);
      expect(user.lockUntil).toBeNull();
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.LOGIN_SUCCESS);
      expect(events[0].payload.ip).toBe('1.2.3.4');
    });

    it('returns the user for chaining', () => {
      const user = new UserAggregate(baseProps);
      expect(user.recordLoginSuccess('0.0.0.0')).toBe(user);
    });
  });

  describe('recordLoginFailure()', () => {
    it('increments loginAttempts and emits LOGIN_FAILED', () => {
      const user = new UserAggregate(baseProps);
      user.recordLoginFailure('1.2.3.4');
      expect(user.loginAttempts).toBe(1);
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.LOGIN_FAILED);
      expect(events[0].payload.attempts).toBe(1);
    });

    it('locks account after reaching maxAttempts (default 5)', () => {
      const user = new UserAggregate({ ...baseProps, loginAttempts: 4 });
      user.recordLoginFailure('1.2.3.4');
      expect(user.loginAttempts).toBe(5);
      expect(user.locked).toBe(true);
      expect(user.lockUntil).toBeTruthy();
      const events = user.getAndClearDomainEvents();
      expect(events.some(e => e.type === AuthEvents.USER_LOCKED)).toBe(true);
    });

    it('locks account at custom maxAttempts', () => {
      const user = new UserAggregate({ ...baseProps, loginAttempts: 2 });
      user.recordLoginFailure('1.2.3.4', 3);
      expect(user.locked).toBe(true);
    });

    it('does NOT lock before reaching maxAttempts', () => {
      const user = new UserAggregate(baseProps);
      user.recordLoginFailure('1.2.3.4', 5);
      expect(user.locked).toBe(false);
    });

    it('returns user for chaining', () => {
      const user = new UserAggregate(baseProps);
      expect(user.recordLoginFailure('1.2.3.4')).toBe(user);
    });
  });

  describe('enableMFA()', () => {
    it('sets mfaEnabled, mfaSecret, recoveryCodes and emits MFA_ENABLED', () => {
      const user = new UserAggregate(baseProps);
      user.enableMFA('SECRET123', ['code1', 'code2']);
      expect(user.mfaEnabled).toBe(true);
      expect(user.mfaSecret).toBe('SECRET123');
      expect(user.recoveryCodes).toEqual(['code1', 'code2']);
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.MFA_ENABLED);
      expect(events[0].payload.method).toBe('totp');
    });
  });

  describe('disableMFA()', () => {
    it('clears mfa fields and emits MFA_DISABLED', () => {
      const user = new UserAggregate({ ...baseProps, mfaEnabled: true, mfaSecret: 'S', recoveryCodes: ['c1'] });
      user.disableMFA();
      expect(user.mfaEnabled).toBe(false);
      expect(user.mfaSecret).toBeNull();
      expect(user.recoveryCodes).toEqual([]);
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.MFA_DISABLED);
    });
  });

  describe('changePassword()', () => {
    it('updates passwordHash and emits PASSWORD_CHANGED', () => {
      const user = new UserAggregate(baseProps);
      user.changePassword('newHash');
      expect(user.passwordHash).toBe('newHash');
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.PASSWORD_CHANGED);
    });
  });

  describe('resetPassword()', () => {
    it('updates hash, resets loginAttempts/lock, emits PASSWORD_RESET', () => {
      const user = new UserAggregate({ ...baseProps, loginAttempts: 3, locked: true });
      user.resetPassword('resetHash');
      expect(user.passwordHash).toBe('resetHash');
      expect(user.loginAttempts).toBe(0);
      expect(user.locked).toBe(false);
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.PASSWORD_RESET);
    });
  });

  describe('unlock()', () => {
    it('unlocks account and emits USER_UNLOCKED', () => {
      const user = new UserAggregate({ ...baseProps, locked: true, loginAttempts: 5 });
      user.unlock();
      expect(user.locked).toBe(false);
      expect(user.lockUntil).toBeNull();
      expect(user.loginAttempts).toBe(0);
      const events = user.getAndClearDomainEvents();
      expect(events[0].type).toBe(AuthEvents.USER_UNLOCKED);
    });
  });

  describe('assignRole() / removeRole()', () => {
    it('adds a role and does not duplicate', () => {
      const user = new UserAggregate(baseProps);
      user.assignRole('admin');
      expect(user.roles).toContain('admin');
      user.assignRole('admin'); // idempotent
      expect(user.roles.filter(r => r === 'admin')).toHaveLength(1);
    });

    it('removes a role', () => {
      const user = new UserAggregate({ ...baseProps, roles: ['user', 'admin'] });
      user.removeRole('admin');
      expect(user.roles).not.toContain('admin');
    });
  });

  describe('isLocked()', () => {
    it('returns false for non-locked user', () => {
      const user = new UserAggregate(baseProps);
      expect(user.isLocked()).toBe(false);
    });

    it('returns true when locked and lockUntil is in the future', () => {
      const future = new Date(Date.now() + 60000);
      const user = new UserAggregate({ ...baseProps, locked: true, lockUntil: future });
      expect(user.isLocked()).toBe(true);
    });

    it('auto-unlocks when lockUntil is in the past', () => {
      const past = new Date(Date.now() - 1000);
      const user = new UserAggregate({ ...baseProps, locked: true, lockUntil: past });
      expect(user.isLocked()).toBe(false);
      expect(user.locked).toBe(false);
    });
  });

  describe('hasRole()', () => {
    it('returns true for an assigned role', () => {
      const user = new UserAggregate({ ...baseProps, roles: ['user', 'admin'] });
      expect(user.hasRole('admin')).toBe(true);
    });

    it('returns false for unassigned role', () => {
      const user = new UserAggregate(baseProps);
      expect(user.hasRole('superadmin')).toBe(false);
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('returns events and clears them', () => {
      const user = UserAggregate.create(baseProps);
      const events = user.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(user.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('toJSON()', () => {
    it('returns a plain object with required fields', () => {
      const user = new UserAggregate(baseProps);
      const json = user.toJSON();
      expect(json.id).toBe(baseProps.id);
      expect(json.username).toBe(baseProps.username);
      expect(json.email).toBe(baseProps.email);
      expect(json).not.toHaveProperty('passwordHash');
      expect(json).not.toHaveProperty('mfaSecret');
    });
  });
});
