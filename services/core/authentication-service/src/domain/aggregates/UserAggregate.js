'use strict';
const { AuthEvents } = require('../events/AuthEvents');
const { randomUUID } = require('crypto');

class UserAggregate {
  constructor(props) {
    this._id = props.id;
    this._username = props.username;
    this._email = props.email;
    this._passwordHash = props.passwordHash;
    this._roles = props.roles || ['user'];
    this._mfaEnabled = props.mfaEnabled || false;
    this._mfaSecret = props.mfaSecret || null;
    this._recoveryCodes = props.recoveryCodes || [];
    this._locked = props.locked || false;
    this._lockUntil = props.lockUntil || null;
    this._loginAttempts = props.loginAttempts || 0;
    this._createdAt = props.createdAt || new Date();
    this._updatedAt = props.updatedAt || new Date();
    this._domainEvents = [];
  }

  static create(props) {
    const user = new UserAggregate({ ...props, createdAt: new Date(), updatedAt: new Date() });
    user._domainEvents.push({ type: AuthEvents.USER_CREATED, payload: { userId: props.id, username: props.username, email: props.email, roles: props.roles || ['user'] }, occurredAt: new Date(), eventId: randomUUID() });
    return user;
  }

  recordLoginSuccess(ip) {
    this._loginAttempts = 0;
    this._locked = false;
    this._lockUntil = null;
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.LOGIN_SUCCESS, payload: { userId: this._id, username: this._username, ip }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  recordLoginFailure(ip, maxAttempts = 5) {
    this._loginAttempts += 1;
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.LOGIN_FAILED, payload: { userId: this._id, username: this._username, ip, attempts: this._loginAttempts }, occurredAt: new Date(), eventId: randomUUID() });
    if (this._loginAttempts >= maxAttempts) {
      this._locked = true;
      this._lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 min
      this._domainEvents.push({ type: AuthEvents.USER_LOCKED, payload: { userId: this._id, username: this._username, ip, lockUntil: this._lockUntil }, occurredAt: new Date(), eventId: randomUUID() });
    }
    return this;
  }

  enableMFA(secret, recoveryCodes = []) {
    this._mfaEnabled = true;
    this._mfaSecret = secret;
    this._recoveryCodes = recoveryCodes;
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.MFA_ENABLED, payload: { userId: this._id, method: 'totp' }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  disableMFA() {
    this._mfaEnabled = false;
    this._mfaSecret = null;
    this._recoveryCodes = [];
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.MFA_DISABLED, payload: { userId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  changePassword(newHash) {
    this._passwordHash = newHash;
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.PASSWORD_CHANGED, payload: { userId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  resetPassword(newHash) {
    this._passwordHash = newHash;
    this._loginAttempts = 0;
    this._locked = false;
    this._lockUntil = null;
    this._updatedAt = new Date();
    this._domainEvents.push({ type: AuthEvents.PASSWORD_RESET, payload: { userId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  unlock() {
    this._locked = false;
    this._lockUntil = null;
    this._loginAttempts = 0;
    this._domainEvents.push({ type: AuthEvents.USER_UNLOCKED, payload: { userId: this._id }, occurredAt: new Date(), eventId: randomUUID() });
    return this;
  }

  assignRole(role) {
    if (!this._roles.includes(role)) {
      this._roles = [...this._roles, role];
      this._updatedAt = new Date();
    }
    return this;
  }

  removeRole(role) {
    this._roles = this._roles.filter(r => r !== role);
    this._updatedAt = new Date();
    return this;
  }

  isLocked() {
    if (!this._locked) return false;
    if (this._lockUntil && new Date() > new Date(this._lockUntil)) {
      this._locked = false;
      this._lockUntil = null;
      return false;
    }
    return true;
  }

  hasRole(role) { return this._roles.includes(role); }

  get id() { return this._id; }
  get username() { return this._username; }
  get email() { return this._email; }
  get passwordHash() { return this._passwordHash; }
  get roles() { return [...this._roles]; }
  get mfaEnabled() { return this._mfaEnabled; }
  get mfaSecret() { return this._mfaSecret; }
  get recoveryCodes() { return [...this._recoveryCodes]; }
  get locked() { return this._locked; }
  get lockUntil() { return this._lockUntil; }
  get loginAttempts() { return this._loginAttempts; }

  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  toJSON() {
    return { id: this._id, username: this._username, email: this._email, roles: this._roles, mfaEnabled: this._mfaEnabled, locked: this._locked, lockUntil: this._lockUntil, loginAttempts: this._loginAttempts, createdAt: this._createdAt, updatedAt: this._updatedAt };
  }
}

module.exports = UserAggregate;
