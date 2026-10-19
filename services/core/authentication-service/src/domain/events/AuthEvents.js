'use strict';
const AuthEvents = {
  USER_CREATED:       'identity.user.created',
  USER_UPDATED:       'identity.user.updated',
  USER_DELETED:       'identity.user.deleted',
  USER_LOCKED:        'identity.account.locked',
  USER_UNLOCKED:      'identity.account.unlocked',
  LOGIN_SUCCESS:      'identity.login.success',
  LOGIN_FAILED:       'identity.login.failed',
  LOGOUT:             'identity.logout',
  MFA_ENABLED:        'identity.mfa.enabled',
  MFA_DISABLED:       'identity.mfa.disabled',
  MFA_VERIFIED:       'identity.mfa.verified',
  PASSWORD_CHANGED:   'identity.password.changed',
  PASSWORD_RESET:     'identity.password.reset',
  SESSION_CREATED:    'identity.session.created',
  SESSION_REVOKED:    'identity.session.revoked',
  PIM_GRANTED:        'security.pim.granted',
  PIM_REVOKED:        'security.pim.revoked',
};
module.exports = { AuthEvents };
