export const assignmentId = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
export const assignmentNow = '2026-10-19T12:00:00.000Z';
export const assignmentContext = { actorUserId: assignmentId(90), tenantId: assignmentId(91) };
export const assignmentEnvelope = <Fields extends object = Record<never, never>>(fields: Fields = {} as Fields) => ({ schemaVersion: 1, ...assignmentContext, ...fields });
export const assignmentV2Envelope = <Fields extends object = Record<never, never>>(fields: Fields = {} as Fields) => ({ schemaVersion: 2, companyLicenseProtocol: 2, ...assignmentContext, ...fields });
export const assignmentOk = (data: unknown, headers = {}, status = 200) => ({ status, data, headers });
export const assignmentDirect = () => ({ sourceType: 'direct' as const, sourceId: 'direct' as const, grantId: assignmentId(30) });
export const assignmentBlueprintSource = () => ({ sourceType: 'blueprint' as const, sourceId: assignmentId(1), grantId: assignmentId(31) });
export const assignmentBlueprintAccess = () => assignmentEnvelope({ companyBlueprintAssignmentsProtocol: 1,
  permissions: ['company.blueprints.assignments.read', 'company.blueprints.assign'], configurationMode: 'local-only', allocationMode: 'local-only', supportedTargets: ['user'], maxApplications: 25 });
export const assignmentAppAccess = () => assignmentV2Envelope({ permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], allocationMode: 'local-only', supportedTargets: ['user'] });
export const assignmentBinding = () => ({ id: assignmentId(1), tenantId: assignmentId(91), userId: assignmentId(5), blueprintId: assignmentId(2), version: 1,
  eligibilityRevision: '9007199254740993', revision: '1', status: 'active' as const, actorUserId: assignmentId(90), operationId: assignmentId(92), removalOperationId: null,
  createdAt: assignmentNow, removedAt: null, appPoolIds: [assignmentId(20)] });
export const assignmentConfiguration = () => ({ configType: 'screen_lock' as const, payloadJson: '{"minutes":5,"requirePassword":true}', sources: [{ blueprintId: assignmentId(2), configurationId: assignmentId(10) }] });
export const assignmentPreview = () => assignmentEnvelope({ userId: assignmentId(5), blueprintId: assignmentId(2), version: 1, eligibilityRevision: '9007199254740993',
  pools: [{ poolId: assignmentId(20), poolRevision: '9007199254740993', totalSeats: 1, usedSeats: 1, availableSeats: 0, additionalSeats: 0 }],
  effectiveConfigurations: [assignmentConfiguration()], conflicts: [], hasConflicts: false });
export const assignmentRow = () => ({ id: assignmentId(40), userId: assignmentId(5), assignedAt: assignmentNow, assignedBy: assignmentId(90),
  eligibilityRevision: '9007199254740993', sources: [assignmentBlueprintSource(), assignmentDirect()] });
export const assignmentManualPreview = () => assignmentV2Envelope({ poolId: assignmentId(20), poolRevision: '9007199254740993',
  target: { id: assignmentId(5), revision: '99', eligibilityRevision: '9007199254740993', enabled: true, deleted: false }, assignment: assignmentRow() });
export const assignmentReturnRow = (number = 20) => ({ id: assignmentId(number + 100), poolId: assignmentId(number), poolRevision: '9007199254740993', name: 'Büro-App', vendor: 'Firma',
  eligibilityRevision: '9007199254740993', assignedAt: assignmentNow, sources: [assignmentBlueprintSource(), assignmentDirect()] });
export const assignmentRetirementBinding = () => ({ id: assignmentId(1), revision: '1', blueprintId: assignmentId(2), version: 1, eligibilityRevision: '9007199254740993', poolIds: [] });
export const assignmentOffboardAccess = () => assignmentV2Envelope({ companyOffboardingProtocol: 2, scope: 'account-local-licenses-and-blueprint-bindings', requiresFreshMfa: true });
export const assignmentOffboardPreview = () => assignmentV2Envelope({ user: { id: assignmentId(5), name: 'Anna Mitarbeiter', userRevision: '99', eligibilityRevision: '9007199254740993', enabled: true }, licenseCount: 0, bindingCount: 1 });
export const assignmentCheckpoint = () => ({ schemaVersion: 1, workflowId: assignmentId(80), tenantId: assignmentId(91), userId: assignmentId(5), actorUserId: assignmentId(90),
  operationId: assignmentId(81), action: 'disabled', beforeRevision: '99', afterRevision: '100', beforeEligibilityRevision: '9007199254740993',
  afterEligibilityRevision: '9007199254740994', createdAt: assignmentNow, deliveryStatus: 'pending' });
export const assignmentOffboardJob = () => assignmentV2Envelope({ workflow: { id: assignmentId(80), userId: assignmentId(5), createdBy: assignmentId(90), revision: '3', reason: 'Bewusster Mitarbeiteraustritt', phase: 'licenses',
  totalLicenses: 0, completedLicenses: 0, totalBindings: 1, completedBindings: 0, failure: null, createdAt: assignmentNow, updatedAt: assignmentNow, requestedRevision: '99', checkpoint: assignmentCheckpoint(),
  nextAssignments: [], reviewAssignments: [], nextBindings: [assignmentRetirementBinding()] }, currentTarget: { enabled: false, deleted: false, eligibilityRevision: '9007199254740994' } });
export function assignmentDeferred<Value>() {
  let resolve: (value: Value) => void; const promise = new Promise<Value>(accept => { resolve = accept; });
  return { promise, resolve: (value: Value) => resolve(value) };
}
