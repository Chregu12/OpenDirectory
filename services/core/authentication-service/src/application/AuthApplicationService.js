'use strict';
const UserAggregate = require('../domain/aggregates/UserAggregate');
const SessionAggregate = require('../domain/aggregates/SessionAggregate');
const { randomUUID } = require('crypto');
const jwt = require('jsonwebtoken');

class AuthApplicationService {
  constructor({ userRepository, sessionRepository, messageBus, config, logger }) {
    this._userRepo = userRepository;
    this._sessionRepo = sessionRepository;
    this._bus = messageBus;
    this._config = config || {};
    this._log = logger || console;
    this._jwtSecret = config.jwtSecret || process.env.JWT_SECRET || 'changeme';
  }

  async login({ username, password, ip, userAgent, deviceId }) {
    const user = await this._userRepo.findByUsername(username);
    if (!user) {
      this._log.warn(`Login failed — user not found: ${username}`);
      throw Object.assign(new Error('Invalid credentials'), { status: 401 });
    }

    if (user.isLocked()) {
      throw Object.assign(new Error('Account is locked'), { status: 403 });
    }

    // Verify password. Two hash formats coexist in production:
    //   - bcrypt ($2a$/$2b$/$2y$ prefix) — written by the legacy UserService /
    //     AuthenticationManager (createUser, changePassword, admin resets).
    //     This is what the overwhelming majority of real users have.
    //   - scrypt ("salt:derivedHex") — written by the DDD Password value
    //     object (PasswordApplicationService.resetWithToken()).
    //
    // The hash format must be detected up front rather than inferred from a
    // thrown exception: value-objects/Password exports the class directly
    // (module.exports = Password), so `const { Password } = require(...)`
    // used to destructure `undefined`, making `Password.fromHash(...)` throw
    // on *every* login and fall into the bcrypt catch-block below — which
    // coincidentally kept bcrypt logins working while leaving the scrypt/VO
    // path completely dead. Fixing the destructuring bug naively (still
    // trying Password.fromHash().verify() first, unconditionally) would
    // regress in the other direction: verify() does NOT throw on a bcrypt
    // hash, it just returns false (there's no ':' to split cleanly), so
    // real bcrypt-hashed users would silently fail to log in with no
    // fallback ever triggering. Detecting the format explicitly avoids both
    // failure modes.
    let passwordValid = false;
    const storedHash = user.passwordHash || '';
    const isBcryptHash = /^\$2[aby]?\$/.test(storedHash);
    try {
      if (isBcryptHash) {
        const bcrypt = require('bcryptjs');
        passwordValid = await bcrypt.compare(password, storedHash);
      } else {
        const Password = require('../domain/value-objects/Password');
        const pw = Password.fromHash(storedHash);
        passwordValid = await pw.verify(password);
      }
    } catch (e) {
      passwordValid = false;
    }

    if (!passwordValid) {
      user.recordLoginFailure(ip);
      await this._userRepo.save(user);
      await this._publishDomainEvents(user);
      throw Object.assign(new Error('Invalid credentials'), { status: 401 });
    }

    user.recordLoginSuccess(ip);
    await this._userRepo.save(user);
    await this._publishDomainEvents(user);

    // Create session
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8h
    const token = jwt.sign(
      { userId: user.id, username: user.username, roles: user.roles },
      this._jwtSecret,
      { expiresIn: '8h' }
    );

    const session = SessionAggregate.create({
      sessionId: randomUUID(),
      userId: user.id,
      token,
      expiresAt,
      ip,
      userAgent,
    });

    if (this._sessionRepo) await this._sessionRepo.save(session);
    await this._publishDomainEvents(session);

    const userJson = user.toJSON();
    return { user: { ...userJson, id: String(userJson.id) }, token, expiresAt, mfaRequired: user.mfaEnabled };
  }

  async logout(token) {
    if (!this._sessionRepo) return;
    const session = await this._sessionRepo.findByToken(token);
    if (session) {
      session.revoke();
      await this._sessionRepo.save(session);
      await this._publishDomainEvents(session);
    }
  }

  async validateToken(token) {
    try {
      const payload = jwt.verify(token, this._jwtSecret);
      const user = await this._userRepo.findById(payload.userId);
      if (!user || user.isLocked()) return null;
      return { valid: true, userId: String(user.id), username: user.username, roles: user.roles, expiresAt: new Date(payload.exp * 1000).toISOString() };
    } catch (e) {
      return null;
    }
  }

  async _publishDomainEvents(aggregate) {
    if (!this._bus || !this._bus.isConnected()) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const event of events) {
      try { this._bus.publish(event.type, { ...event.payload, _source: 'auth-service' }); } catch (_) {}
    }
  }
}

module.exports = AuthApplicationService;
