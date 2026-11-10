import { VIEWS, visibleViews, VALID_VIEWS } from '@/lib/views';
const base = { subject: 'subject', userId: '11111111-1111-4111-8111-111111111111', demoMode: false, permissions: [] as string[] };
const context = { access: base, platformAdmin: false, configuredServices: [] };
test('keeps unique IDs and legacy deep links', () => {
  expect(new Set(VIEWS.map(view => view.id)).size).toBe(VIEWS.length);
  for (const id of ['fleet', 'roles', 'gpo', 'serviceprincipals', 'company-apps', 'automation']) expect(VALID_VIEWS.has(id)).toBe(true);
});
test('a profile delegate sees delegated and personal tasks', () => {
  const ids = visibleViews({ ...context, access: { ...base, permissions: ['organization.read', 'organization.manage'] } }).map(view => view.id);
  expect(ids).toContain('organization'); expect(ids).toContain('mfa');
  for (const id of ['users', 'company-apps', 'permissions', 'settings', 'registration-reviews']) expect(ids).not.toContain(id);
});
test('an owner gets company tasks without platform privileges', () => {
  const ids = visibleViews({ ...context, access: { ...base, companyOwner: true, permissions: ['users.read', 'groups.read'] } }).map(view => view.id);
  for (const id of ['users', 'applications', 'company-apps', 'automation']) expect(ids).toContain(id);
  for (const id of ['settings', 'registration-reviews', 'permissions', 'infrastructure']) expect(ids).not.toContain(id);
});
test('configuration and disabled modules constrain admin navigation', () => {
  const ids = visibleViews({ ...context, platformAdmin: true, enabledModules: [] }).map(view => view.id);
  expect(ids).not.toContain('antivirus'); expect(ids).not.toContain('devices'); expect(ids).not.toContain('appstore'); expect(ids).toContain('settings');
});
test('only explicit company reviewers see the review queue', () => {
  expect(visibleViews({ ...context, platformAdmin: true }).some(view => view.id === 'registration-reviews')).toBe(false);
  expect(visibleViews({ ...context, access: { ...base, permissions: ['company.registrations.review'] } }).some(view => view.id === 'registration-reviews')).toBe(true);
});

test('Engineering sees its own inventory tasks without unrelated administration',()=>{
 const ids=visibleViews({...context,roles:['device-enrollment-operator']}).map(view=>view.id);
 for(const id of ['devices','device-returns'])expect(ids).toContain(id);
 for(const id of ['settings','users','permissions','applications','company-blueprints','infrastructure'])expect(ids).not.toContain(id);
});
