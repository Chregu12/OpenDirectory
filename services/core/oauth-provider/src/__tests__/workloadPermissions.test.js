'use strict';

const { workloadAuthorizationClaims }=require('../oauthScopes');
test('the explicit derivation purpose grants only its narrow source permission, never a human role',()=>{expect(workloadAuthorizationClaims('licenses.groups.derive')).toEqual({permissions:['licenses.groups.derive']});expect(workloadAuthorizationClaims('licenses.groups.read roles')).toEqual({});});
test.each(['','openid roles','users.delete oauth.admin','licenses.users.*','*'])('workload scope %s grants no ambient role or generic permission',scope=>expect(workloadAuthorizationClaims(scope)).toEqual({}));
test('only the explicit user-eligibility scope maps to a narrowly scoped workload permission',()=>{
  expect(workloadAuthorizationClaims('licenses.users.read')).toEqual({ permissions:['licenses.users.read'] });
  expect(workloadAuthorizationClaims('licenses.users.read roles users.delete')).toEqual({ permissions:['licenses.users.read'] });
});
test('company automation adds only its dedicated purpose; resource access still requires an independent owner grant',()=>{
 expect(workloadAuthorizationClaims('company.automation')).toEqual({permissions:['company.automation']});
 expect(workloadAuthorizationClaims('company.apps.assign users.create')).toEqual({});
});
