'use strict';

const UserAggregate = require('../UserAggregate');
const { AuthEvents } = UserAggregate;

describe('UserAggregate', () => {
  const validProps = {
    id:       'user-1',
    username: 'jdoe',
    email:    'jdoe@example.com'
  };

  // ── create() ───────────────────────────────────────────────────────────────

  describe('create()', () => {
    it('returns a UserAggregate with the correct fields', () => {
      const user = UserAggregate.create(validProps);

      expect(user).toBeInstanceOf(UserAggregate);
      expect(user.id).toBe('user-1');
      expect(user.username).toBe('jdoe');
      expect(user.email).toBe('jdoe@example.com');
      expect(user.loginAttempts).toBe(0);
      expect(user.mfaEnabled).toBe(false);
      expect(user.isLocked()).toBe(false);
    });

    it('pushes a USER_CREATED domain event with occurredAt and eventId', () => {
      const user = UserAggregate.create(validProps);
      const events = user.getAndClearDomainEvents();

      expect(events).toHaveLength(1);
      const [evt] = events;
      expect(evt.type).toBe(AuthEvents.USER_CREATED);
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(typeof evt.eventId).toBe('string');
      expect(evt.eventId).toBeTruthy();
      expect(evt.payload.userId).toBe('user-1');
      expect(evt.payload.username).toBe('jdoe');
    });

    it('throws when username is missing', () => {
      expect(() => UserAggregate.create({ email: 'x@x.com' })).toThrow('username');
    });

    it('throws when email is missing', () => {
      expect(() => UserAggregate.create({ username: 'jdoe' })).toThrow('email');
    });
  });

  // ── recordLoginFailure() ───────────────────────────────────────────────────

  describe('recordLoginFailure()', () => {
    it('increments loginAttempts on each call', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents(); // clear create event

      user.recordLoginFailure();
      expect(user.loginAttempts).toBe(1);

      user.recordLoginFailure();
      expect(user.loginAttempts).toBe(2);
    });

    it('emits a LOGIN_FAILED event on each failure', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      user.recordLoginFailure();
      const events = user.getAndClearDomainEvents();

      expect(events.some(e => e.type === AuthEvents.LOGIN_FAILED)).toBe(true);
    });

    it('locks the account after MAX_LOGIN_ATTEMPTS failures and emits USER_LOCKED', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      for (let i = 0; i < UserAggregate.MAX_LOGIN_ATTEMPTS; i++) {
        user.recordLoginFailure();
      }

      expect(user.isLocked()).toBe(true);
      expect(user.loginAttempts).toBe(UserAggregate.MAX_LOGIN_ATTEMPTS);

      const events = user.getAndClearDomainEvents();
      const lockedEvent = events.find(e => e.type === AuthEvents.USER_LOCKED);
      expect(lockedEvent).toBeDefined();
      expect(lockedEvent.occurredAt).toBeInstanceOf(Date);
      expect(lockedEvent.eventId).toBeTruthy();
    });

    it('does NOT lock the account before MAX_LOGIN_ATTEMPTS', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      for (let i = 0; i < UserAggregate.MAX_LOGIN_ATTEMPTS - 1; i++) {
        user.recordLoginFailure();
      }

      expect(user.isLocked()).toBe(false);
    });
  });

  // ── recordLoginSuccess() ───────────────────────────────────────────────────

  describe('recordLoginSuccess()', () => {
    it('resets loginAttempts to 0', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      user.recordLoginFailure();
      user.recordLoginFailure();
      expect(user.loginAttempts).toBe(2);

      user.getAndClearDomainEvents();
      user.recordLoginSuccess();
      expect(user.loginAttempts).toBe(0);
    });

    it('clears the locked state', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      for (let i = 0; i < UserAggregate.MAX_LOGIN_ATTEMPTS; i++) {
        user.recordLoginFailure();
      }
      expect(user.isLocked()).toBe(true);

      user.getAndClearDomainEvents();
      user.recordLoginSuccess();
      expect(user.isLocked()).toBe(false);
    });

    it('emits a LOGIN_SUCCESS event', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      user.recordLoginSuccess();
      const events = user.getAndClearDomainEvents();
      expect(events.some(e => e.type === AuthEvents.LOGIN_SUCCESS)).toBe(true);
    });
  });

  // ── enableMFA() ────────────────────────────────────────────────────────────

  describe('enableMFA()', () => {
    it('sets mfaEnabled to true and stores the secret', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      user.enableMFA('TOTP_SECRET_ABC', ['code1', 'code2']);

      expect(user.mfaEnabled).toBe(true);
      expect(user.mfaSecret).toBe('TOTP_SECRET_ABC');
      expect(user.mfaBackupCodes).toEqual(['code1', 'code2']);
    });

    it('emits a MFA_ENABLED event with occurredAt and eventId', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents();

      user.enableMFA('SECRET', []);
      const events = user.getAndClearDomainEvents();

      const mfaEvent = events.find(e => e.type === AuthEvents.MFA_ENABLED);
      expect(mfaEvent).toBeDefined();
      expect(mfaEvent.occurredAt).toBeInstanceOf(Date);
      expect(mfaEvent.eventId).toBeTruthy();
    });

    it('throws when secret is not provided', () => {
      const user = UserAggregate.create(validProps);
      expect(() => user.enableMFA(null, [])).toThrow('secret');
    });
  });

  // ── getAndClearDomainEvents() ──────────────────────────────────────────────

  describe('getAndClearDomainEvents()', () => {
    it('returns all pending events and then clears them', () => {
      const user = UserAggregate.create(validProps);

      const firstCall = user.getAndClearDomainEvents();
      expect(firstCall.length).toBeGreaterThan(0);

      const secondCall = user.getAndClearDomainEvents();
      expect(secondCall).toHaveLength(0);
    });

    it('accumulates events across multiple commands', () => {
      const user = UserAggregate.create(validProps);
      user.getAndClearDomainEvents(); // clear create event

      user.recordLoginFailure();
      user.recordLoginSuccess();
      user.enableMFA('S', []);

      const events = user.getAndClearDomainEvents();
      const types = events.map(e => e.type);

      expect(types).toContain(AuthEvents.LOGIN_FAILED);
      expect(types).toContain(AuthEvents.LOGIN_SUCCESS);
      expect(types).toContain(AuthEvents.MFA_ENABLED);

      // Cleared after retrieval
      expect(user.getAndClearDomainEvents()).toHaveLength(0);
    });
  });
});
