'use strict';

const { probe } = require('../../../scripts/license-fulfillment-probe');
const targetId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const connectorId = '33333333-3333-4333-8333-333333333333';
function fixture(patch = {}) {
  return { targetId, config: { tenantId, connectorId },
    store: { get: jest.fn(async () => ({ tenantId })), row: jest.fn(async () => ({ enabled: true, business_tenant_id: null, connector_id: connectorId, tenant_id: tenantId, object_id: targetId, sku_id: connectorId, disabled_plans: [], ...patch })), available: jest.fn(async () => true) },
    graph: { tenantId, inspect: jest.fn(async () => ({ present: true, direct: false, inherited: true })), mutate: jest.fn() } };
}
test('probe only reads the explicitly mapped object and emits a bounded observation', async () => {
  const input = fixture();
  expect(await probe(input)).toEqual({ targetId, tenantId, observation: { present: true, direct: false, inherited: true } });
  expect(input.graph.inspect).toHaveBeenCalledWith(targetId, connectorId, []);
  expect(input.graph.mutate).not.toHaveBeenCalled();
});
test.each([{ enabled: false }, { business_tenant_id: tenantId }, { connector_id: tenantId }, { tenant_id: connectorId }])('rejects mismatched, disabled or company-owned targets before Graph: %j', async patch => {
  const input = fixture(patch);
  await expect(probe(input)).rejects.toThrow('graph_probe_binding_rejected');
  expect(input.graph.inspect).not.toHaveBeenCalled();
});
test('rejects a configuration/Graph tenant mismatch and active connector backoff', async () => {
  const input = fixture(); input.graph.tenantId = connectorId;
  await expect(probe(input)).rejects.toThrow('graph_probe_binding_rejected');
  input.graph.tenantId = tenantId; input.store.available.mockResolvedValue(false);
  await expect(probe(input)).rejects.toThrow('graph_probe_backoff_active');
  expect(input.graph.inspect).not.toHaveBeenCalled();
});
