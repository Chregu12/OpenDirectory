'use strict';

const { getLicensePermissions, isOwnLicenseRequest } = require('../middleware/licenseAccess');

describe('License permissions', () => {
  test('source consent duties do not imply allocation and applications never inherit human grants',()=>{
    expect(getLicensePermissions({roles:['license-scope-administrator']})).toContain('licenses.sources.manage');expect(getLicensePermissions({roles:['license-scope-administrator']})).not.toContain('licenses.assignments.manage');expect(getLicensePermissions({roles:['admin']})).not.toContain('licenses.sources.manage');
    expect(getLicensePermissions({actor_type:'application',roles:['admin'],permissions:['licenses.assignments.manage']})).toEqual([]);
  });
  test('delegates offboarding without granting allocation, catalog, or reactivation rights', () => {
    expect(getLicensePermissions({ permissions: ['users.offboard'] })).toEqual(['licenses.subjects.offboard']);
    expect(getLicensePermissions({ scope: 'users.offboard' })).toEqual([]);
    expect(getLicensePermissions({ roles: ['user-lifecycle-operator'] })).toEqual(['licenses.subjects.offboard']);
    expect(getLicensePermissions({ realm_access: { roles: ['user-lifecycle-operator'] } })).toEqual(['licenses.subjects.offboard']);
  });
  test.each([null, {}, { roles: 'admin' }, { roles: ['user'] }, { roles: ['constructor'] }, { roles: [{ toString: null }] }, { permissions: 'licenses.catalog.manage' }, { scope: 'licenses.catalog.manage', scopes: ['licenses.requests.review'] }])('denies missing, malformed and client-requested grants: %j', user => {
    expect(getLicensePermissions(user)).toEqual([]);
  });

  test('separates license management from approval and identity administration', () => {
    const permissions = getLicensePermissions({ roles: ['license-manager'] });
    expect(permissions).toContain('licenses.catalog.manage');
    expect(permissions).toContain('licenses.assignments.manage');
    expect(permissions).not.toContain('licenses.requests.review');
    expect(permissions.every(permission => permission.startsWith('licenses.'))).toBe(true);
  });

  test('limits approvers to reviewing license requests', () => {
    expect(getLicensePermissions({ roles: ['license-approver'] })).toEqual(['licenses.requests.read', 'licenses.requests.review']);
  });

  test('supports server-issued individual permissions and realm roles', () => {
    expect(getLicensePermissions({ permissions: ['licenses.catalog.read', '*', 'users.manage'], realm_access: { roles: ['license-approver'] } }))
      .toEqual(expect.arrayContaining(['licenses.catalog.read', 'licenses.requests.read', 'licenses.requests.review']));
    expect(getLicensePermissions({ permissions: ['*', 'users.manage'] })).toEqual([]);
  });

  test('supports a license-only administrator and existing bootstrap administrators', () => {
    expect(getLicensePermissions({ roles: ['license-administrator'] })).toEqual(getLicensePermissions({ roles: ['admin'] }).filter(permission=>!permission.startsWith('licenses.fulfillment.') && !permission.startsWith('licenses.reviews.') && !permission.startsWith('licenses.delegations.') && !permission.startsWith('licenses.scopepim.') && !permission.startsWith('licenses.scopepolicies.') && !permission.startsWith('licenses.scopereviews.')&&!permission.startsWith('licenses.sources.')));
    expect(getLicensePermissions({roles:['license-administrator']})).not.toContain('licenses.scopepim.review');
    expect(getLicensePermissions({roles:['admin']})).not.toContain('licenses.scopepim.review');
    expect(getLicensePermissions({roles:['admin','license-scope-activation-reviewer']})).toContain('licenses.scopepim.review');
    expect(getLicensePermissions({roles:['admin']})).not.toContain('licenses.scopepolicies.manage');
    expect(getLicensePermissions({roles:['license-scope-policy-administrator']})).toEqual(['licenses.scopepolicies.read','licenses.scopepolicies.manage']);
    expect(getLicensePermissions({ roles: ['license-administrator'] })).toContain('licenses.requests.delegate');
  });
  test('license review duties do not inherit ordinary allocation or each other', () => {
    expect(getLicensePermissions({ roles: ['license-review-administrator'] })).toEqual(['licenses.reviews.policies.read','licenses.reviews.policies.manage','licenses.reviews.all.read']);
    expect(getLicensePermissions({ roles: ['license-reviewer'] })).toEqual(['licenses.reviews.assigned.read','licenses.reviews.decide']);
    expect(getLicensePermissions({ roles: ['license-review-reader'] })).toEqual(['licenses.reviews.policies.read','licenses.reviews.all.read']);
  });
  test('administrative review configuration and votes are explicit independent duties, not implicit root writes',()=>{
    expect(getLicensePermissions({roles:['license-delegation-review-administrator']})).toEqual(['licenses.scopereviews.policies.read','licenses.scopereviews.policies.manage','licenses.scopereviews.all.read']);
    expect(getLicensePermissions({roles:['license-delegation-reviewer']})).toEqual(['licenses.scopereviews.assigned.read','licenses.scopereviews.decide']);
    expect(getLicensePermissions({roles:['license-delegation-review-reader']})).toEqual(['licenses.scopereviews.policies.read','licenses.scopereviews.all.read']);
    expect(getLicensePermissions({roles:['admin']})).not.toContain('licenses.scopereviews.decide');expect(getLicensePermissions({roles:['admin']})).not.toContain('licenses.scopereviews.policies.manage');
    expect(getLicensePermissions({roles:['admin','license-delegation-reviewer']})).toContain('licenses.scopereviews.decide');
  });
});

describe('Independent approval', () => {
  test('blocks the requester and a user who benefits from a delegated request', () => {
    const licenseRequest = { requester_id: 'manager', assignee_type: 'user', assignee_id: 'alice' };
    expect(isOwnLicenseRequest('manager', licenseRequest)).toBe(true);
    expect(isOwnLicenseRequest('alice', licenseRequest)).toBe(true);
    expect(isOwnLicenseRequest('reviewer', licenseRequest)).toBe(false);
  });

  test('does not confuse user IDs with device or group IDs', () => {
    expect(isOwnLicenseRequest('alice', { requester_id: 'manager', assignee_type: 'device', assignee_id: 'alice' })).toBe(false);
  });
});
