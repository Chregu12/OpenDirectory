'use strict';
const { AuthEvents } = require('../events/AuthEvents');

class SessionAggregate {
  constructor(props) {
    this._sessionId = props.sessionId;
    this._userId = props.userId;
    this._token = props.token;
    this._refreshToken = props.refreshToken || null;
    this._expiresAt = props.expiresAt;
    this._createdAt = props.createdAt || new Date();
    this._revokedAt = props.revokedAt || null;
    this._ip = props.ip || null;
    this._userAgent = props.userAgent || null;
    this._domainEvents = [];
  }

  static create(props) {
    const session = new SessionAggregate({ ...props, createdAt: new Date() });
    session._domainEvents.push({ type: AuthEvents.SESSION_CREATED, payload: { sessionId: session._sessionId, userId: session._userId, ip: session._ip } });
    return session;
  }

  revoke() {
    this._revokedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.SESSION_REVOKED, payload: { sessionId: this._sessionId, userId: this._userId } });
    return this;
  }

  isValid() {
    return !this._revokedAt && new Date() < new Date(this._expiresAt);
  }

  get sessionId() { return this._sessionId; }
  get userId() { return this._userId; }
  get token() { return this._token; }
  get expiresAt() { return this._expiresAt; }
  get revokedAt() { return this._revokedAt; }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }
}

module.exports = SessionAggregate;
