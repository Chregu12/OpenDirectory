'use strict';

const SessionAggregate = require('../domain/aggregates/SessionAggregate');
const { AuthEvents } = require('../domain/events/AuthEvents');

describe('SessionAggregate', () => {
  const futureDate = new Date(Date.now() + 8 * 60 * 60 * 1000);

  const baseProps = {
    sessionId: 'session-abc',
    userId: 'user-1',
    token: 'jwt.token.here',
    expiresAt: futureDate,
    ip: '192.168.1.1',
    userAgent: 'Mozilla/5.0',
  };

  describe('constructor', () => {
    it('sets all properties from props', () => {
      const session = new SessionAggregate(baseProps);
      expect(session.sessionId).toBe(baseProps.sessionId);
      expect(session.userId).toBe(baseProps.userId);
      expect(session.token).toBe(baseProps.token);
      expect(session.expiresAt).toBe(baseProps.expiresAt);
      expect(session.revokedAt).toBeNull();
    });

    it('defaults refreshToken to null and revokedAt to null', () => {
      const session = new SessionAggregate(baseProps);
      expect(session._refreshToken).toBeNull();
      expect(session.revokedAt).toBeNull();
    });
  });

  describe('static create()', () => {
    it('creates a SessionAggregate and emits SESSION_CREATED domain event', () => {
      const session = SessionAggregate.create(baseProps);
      expect(session).toBeInstanceOf(SessionAggregate);
      const events = session.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(AuthEvents.SESSION_CREATED);
      expect(events[0].payload.sessionId).toBe(baseProps.sessionId);
      expect(events[0].payload.userId).toBe(baseProps.userId);
    });
  });

  describe('revoke()', () => {
    it('sets revokedAt and emits SESSION_REVOKED', () => {
      const session = SessionAggregate.create(baseProps);
      session.getAndClearDomainEvents(); // clear create event
      session.revoke();
      expect(session.revokedAt).toBeInstanceOf(Date);
      const events = session.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(AuthEvents.SESSION_REVOKED);
      expect(events[0].payload.sessionId).toBe(baseProps.sessionId);
    });

    it('returns session for chaining', () => {
      const session = new SessionAggregate(baseProps);
      expect(session.revoke()).toBe(session);
    });
  });

  describe('isValid()', () => {
    it('returns true for a live, non-revoked session', () => {
      const session = new SessionAggregate(baseProps);
      expect(session.isValid()).toBe(true);
    });

    it('returns false for a revoked session', () => {
      const session = new SessionAggregate({ ...baseProps, revokedAt: new Date() });
      expect(session.isValid()).toBe(false);
    });

    it('returns false for an expired session', () => {
      const past = new Date(Date.now() - 1000);
      const session = new SessionAggregate({ ...baseProps, expiresAt: past });
      expect(session.isValid()).toBe(false);
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('returns events then clears them', () => {
      const session = SessionAggregate.create(baseProps);
      const events = session.getAndClearDomainEvents();
      expect(events.length).toBeGreaterThan(0);
      expect(session.getAndClearDomainEvents()).toHaveLength(0);
    });
  });
});
