export const microsoftId = (value: number) => `00000000-0000-4000-8000-${value.toString().padStart(12, '0')}`;
export const microsoftContext = { actorUserId: microsoftId(1), tenantId: microsoftId(2) };
export const microsoftEnvelope = { schemaVersion: 1, companyMicrosoftProtocol: 1, ...microsoftContext };
const time = '2026-11-16T00:00:00.000Z';
export const microsoftConnection = () => ({ id: microsoftId(3), tenantId: microsoftId(2), revision: '9007199254740993', status: 'active', createdAt: time, updatedAt: time,
  tenantGeneration: '1', microsoftTenantId: microsoftId(4), readClientId: microsoftId(5), writeClientId: microsoftId(6) });
export const microsoftState = () => ({ ...microsoftEnvelope, state: 'connected', microsoftTenantId: microsoftId(4), readClientId: microsoftId(5), writeClientId: microsoftId(6), connection: microsoftConnection() });
export const microsoftPool = () => ({ id: microsoftId(7), tenantId: microsoftId(2), revision: '1', status: 'active', createdAt: time, updatedAt: time, connectionId: microsoftId(3), poolId: microsoftId(8), skuId: microsoftId(9), disabledPlans: [] });
export const microsoftPerson = () => ({ id: microsoftId(10), tenantId: microsoftId(2), revision: '1', status: 'active', createdAt: time, updatedAt: time, connectionId: microsoftId(3), userId: microsoftId(11), objectId: microsoftId(12) });
export const microsoftMappings = () => ({ ...microsoftEnvelope, poolId: microsoftId(8), pool: null, users: [microsoftPerson()], page: 1, hasMore: false });
export const microsoftProducts = () => ({ ...microsoftEnvelope, microsoftTenantId: microsoftId(4), checkedAt: time, products: [{ skuId: microsoftId(9), skuPartNumber: 'BUSINESS_TEST', appliesTo: 'User', capabilityStatus: 'Enabled', prepaidUnits: { enabled: 12, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 3 }] });
export const microsoftHistory = () => ({ ...microsoftEnvelope, events: [], page: 1, hasMore: false });
export const microsoftPreview = () => ({ ...microsoftEnvelope, poolId: microsoftId(8), userId: microsoftId(11), connection: microsoftConnection(), pool: microsoftPool(), user: microsoftPerson(), target: null,
  local: { raw: { poolId: microsoftId(8), poolRevision: '2', target: { id: microsoftId(11), revision: '1', eligibilityRevision: '1', enabled: true, deleted: false }, assignment: { id: microsoftId(13), eligibilityRevision: '1' },
    origins: [{ sourceType: 'direct', sourceId: 'direct', grantId: microsoftId(14), eligibilityRevision: '1', live: true, deadline: null, bindingValid: true, rule: null }] }, groups: [], desired: true },
  remote: { present: false, direct: false, active: false, plansMatch: false, inherited: false, accountEnabled: true }, stock: microsoftProducts().products[0], fingerprint: 'a'.repeat(64), action: 'assign', checkedAt: time });
export const microsoftResponse = (data: unknown, status = 200, headers = {}) => ({ data, status, headers });
export const microsoftSyncReceipt = (operationId = microsoftId(100)) => ({ ...microsoftEnvelope, historical: false, result: { operationId, poolId: microsoftId(8), userId: microsoftId(11), action: 'assign', targetId: microsoftId(30), targetRevision: '2',
  status: 'verifying', owned: true, pendingOperationId: operationId, uncertainOperationId: null, errorCode: 'provider_verification_pending', eventId: microsoftId(31), kind: 'acknowledged', retryAfter: null, retryAt: null } });
