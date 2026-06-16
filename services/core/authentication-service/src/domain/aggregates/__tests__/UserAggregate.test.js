'use strict';

const UserAggregate = require('../UserAggregate');
const { AuthEvents } = require('../../events/AuthEvents');

describe('UserAggregate', () => {
  const validProps = {
    id:           'user-1',
    username:     'jdoe',
    email:        'jdoe@example.com',
    passwordHash: 'hashed_password'
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
      expect(user.locked).toBe(false);
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

    it('defaults roles to ["user"] when not provided', () => {
      const user = UserAggregate.create(validProps);
      const [evt] = user.getAndClearDomainEvents();
      expect(evt.payload.roles).toEqual(['user']);
    });
  });

  // ── recordLoginFailure() ───────────────────────────────────────────────────

  describe('recordLoginFailure()', () => {
    it('increments loginAttempts on each call', () => {
      const user = new UserAggregate(validProps);

      user.recordLoginFailure('1.2.3.4');
      expect(user.loginAttempts).toBe(1);

      user.recordLoginFailure('1.2.3.4');
      expect(user.loginAttempts).toBe(2);
    });

    it('emits a LOGIN_FAILED event with attempt count', () => {
      const user = new UserAggregate(validProps);

      user.recordLoginFailure('10.0.0.1');
      const events = user.getAndClearDomainEvents();

      const failedEvt = events.find(e => e.type === AuthEvents.LOGIN_FAILED);
      expect(failedEvt).toBeDefined();
      expect(failedEvt.occurredAt).toBeInstanceOf(Date);
      expect(failedEvt.eventId).toBeTruthy();
      expect(failedEvt.payload.attempts).toBe(1);
    });

    it('locks the account after 5 failures and emits USER_LOCKED', () => {
      const user = new UserAggregate({ ...validProps, loginAttempts: 4 });

      user.recordLoginFailure('10.0.0.1');

      expect(user.locked).toBe(true);
      expect(user.loginAttempts).toBe(5);

      const events = user.getAndClearDomainEvents();
      const lockedEvt = events.find(e => e.type === AuthEvents.USER_LOCKED);
      expect(lockedEvt).toBeDefined();
      expect(lockedEvt.occurredAt).toBeInstanceOf(Date);
      expect(lockedEvt.eventId).toBeTruthy();
      expect(lockedEvt.payload.lockUntil).toBeInstanceOf(Date);
    });

    it('does NOT lock the account before the threshold', () => {
      const user = new UserAggregate(validProps);

      for (let i = 0; i < 4; i++) {
        user.recordLoginFailure('10.0.0.1');
      }

      expect(user.locked).toBe(false);
    });
  });

  // ── recordLoginSuccess() ───────────────────────────────────────────────────

  describe('recordLoginSuccess()', () => {
    it('resets loginAttempts to 0', () => {
      const user = new UserAggregate({ ...validProps, loginAttempts: 3 });

      user.recordLoginSuccess('1.2.3.4');
      expect(user.loginAttempts).toBe(0);
    });

    it('clears the locked state', () => {
      const user = new UserAggregate({ ...validProps, locked: true, loginAttempts: 5 });

      user.recordLoginSuccess('1.2.3.4');
      expect(user.locked).toBe(false);
      expect(user.lockUntil).toBeNull();
    });

    it('emits a LOGIN_SUCCESS event', () => {
      const user = new UserAggregate(validProps);

      user.recordLoginSuccess('5.5.5.5');
      const events = user.getAndClearDomainEvents();
      const successEvt = events.find(e => e.type === AuthEvents.LOGIN_SUCCESS);
      expect(successEvt).toBeDefined();
      expect(successEvt.occurredAt).toBeInstanceOf(Date);
      expect(successEvt.eventId).toBeTruthy();
    });
  });

  // ── enableMFA() ────────────────────────────────────────────────────────────

  describe('enableMFA()', () => {
    it('sets mfaEnabled to true and stores the secret and recovery codes', () => {
      const user = new UserAggregate(validProps);

      user.enableMFA('TOTP_SECRET', ['code1', 'code2']);

      expect(user.mfaEnabled).toBe(true);
      expect(user.mfaSecret).toBe('TOTP_SECRET');
      expect(user.recoveryCodes).toEqual(['code1', 'code2']);
    });

    it('emits a MFA_ENABLED event with occurredAt and eventId', () => {
      const user = new UserAggregate(validProps);

      user.enableMFA('SECRET', []);
      const events = user.getAndClearDomainEvents();

      const mfaEvt = events.find(e => e.type === AuthEvents.MFA_ENABLED);
      expect(mfaEvt).toBeDefined();
      expect(mfaEvt.occurredAt).toBeInstanceOf(Date);
      expect(mfaEvt.eventId).toBeTruthy();
      expect(mfaEvt.payload.method).toBe('totp');
    });

    it('defaults recovery codes to [] when not provided', () => {
      const user = new UserAggregate(validProps);
      user.enableMFA('SECRET');
      expect(user.recoveryCodes).toEqual([]);
    });
  });

  // ── getAndClearDomainEvents() ──────────────────────────────────────────────

  describe('getAndClearDomainEvents()', () => {
    it('returns events and clears them — subsequent call returns []', () => {
      const user = UserAggregate.create(validProps);

      const firstCall = user.getAndClearDomainEvents();
      expect(firstCall.length).toBeGreaterThan(0);

      const secondCall = user.getAndClearDomainEvents();
      expect(secondCall).toHaveLength(0);
    });

    it('accumulates events across multiple commands', () => {
      const user = new UserAggregate(validProps);

      user.recordLoginFailure('1.1.1.1');
      user.recordLoginSuccess('1.1.1.1');
      user.enableMFA('S', []);

      const events = user.getAndClearDomainEvents();
      const types = events.map(e => e.type);

      expect(types).toContain(AuthEvents.LOGIN_FAILED);
      expect(types).toContain(AuthEvents.LOGIN_SUCCESS);
      expect(types).toContain(AuthEvents.MFA_ENABLED);

      expect(user.getAndClearDomainEvents()).toHaveLength(0);
    });
  });
});
