'use strict';

const PolicyApplicationService = require('../application/PolicyApplicationService');

function makeService(overrides = {}) {
  const db = {
    query: jest.fn(),
  };
  const bus = {
    isConnected: jest.fn(() => true),
    publish: jest.fn(),
  };
  const logger = { warn: jest.fn(), info: jest.fn(), error: jest.fn() };
  const svc = new PolicyApplicationService({
    policyRepository: {},
    blueprintRepository: {},
    messageBus: bus,
    db,
    logger,
    ...overrides,
  });
  return { svc, db, bus, logger };
}

describe('PolicyApplicationService', () => {
  describe('createPolicy()', () => {
    it('inserts policy and publishes policy.created event', async () => {
      const { svc, db, bus } = makeService();
      const row = { id: 'pol-1', name: 'Test Policy', type: 'security' };
      db.query.mockResolvedValue({ rows: [row] });

      const result = await svc.createPolicy({
        name: 'Test Policy',
        type: 'security',
        platform: 'windows',
        createdBy: 'admin',
      });

      expect(result).toEqual(row);
      expect(db.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO policies'),
        expect.any(Array)
      );
      expect(bus.publish).toHaveBeenCalledWith('policy.created', expect.objectContaining({
        policyId: 'pol-1',
        _source: 'policy-service',
      }));
    });

    it('does not publish when bus is not connected', async () => {
      const { svc, db, bus } = makeService();
      bus.isConnected.mockReturnValue(false);
      db.query.mockResolvedValue({ rows: [{ id: 'pol-1', name: 'T', type: 't' }] });

      await svc.createPolicy({ name: 'T', type: 't' });
      expect(bus.publish).not.toHaveBeenCalled();
    });
  });

  describe('evaluateCompliance()', () => {
    it('returns compliant when no violations', async () => {
      const { svc, db, bus } = makeService();
      db.query.mockResolvedValue({ rows: [] }); // no active policies

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-1',
        devicePlatform: 'windows',
        deviceProperties: {},
      });

      expect(result.isCompliant).toBe(true);
      expect(result.violations).toEqual([]);
      expect(bus.publish).toHaveBeenCalledWith('device.compliant', expect.objectContaining({ deviceId: 'dev-1' }));
    });

    it('returns non-compliant when rule is violated', async () => {
      const { svc, db, bus } = makeService();
      db.query.mockResolvedValue({
        rows: [{
          id: 'pol-1',
          name: 'Encryption Check',
          rules: [{ key: 'diskEncrypted', operator: 'equals', value: true, severity: 'high' }],
        }],
      });

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-1',
        devicePlatform: 'windows',
        deviceProperties: { diskEncrypted: false }, // violates equals:true
      });

      expect(result.isCompliant).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(bus.publish).toHaveBeenCalledWith('device.non_compliant', expect.objectContaining({ deviceId: 'dev-1' }));
    });

    it('parses rules from JSON string when needed', async () => {
      const { svc, db } = makeService();
      db.query.mockResolvedValue({
        rows: [{
          id: 'pol-1',
          name: 'P',
          rules: JSON.stringify([{ key: 'osVersion', operator: 'exists', severity: 'low' }]),
        }],
      });

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-1',
        devicePlatform: 'all',
        deviceProperties: {}, // osVersion does not exist
      });

      expect(result.isCompliant).toBe(false);
    });
  });

  describe('_checkRule()', () => {
    it('returns false when rule has no key', () => {
      const { svc } = makeService();
      expect(svc._checkRule({}, {})).toBe(false);
    });

    it('equals: returns true (violated) when actual !== value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'x', operator: 'equals', value: true }, { x: false })).toBe(true);
    });

    it('equals: returns false (ok) when actual === value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'x', operator: 'equals', value: true }, { x: true })).toBe(false);
    });

    it('not_equals: returns true (violated) when actual === value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'x', operator: 'not_equals', value: 'blocked' }, { x: 'blocked' })).toBe(true);
    });

    it('greater_than: returns true (violated) when actual <= value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'age', operator: 'greater_than', value: 5 }, { age: 3 })).toBe(true);
    });

    it('less_than: returns true (violated) when actual >= value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'size', operator: 'less_than', value: 10 }, { size: 15 })).toBe(true);
    });

    it('contains: returns true (violated) when string does not contain value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 's', operator: 'contains', value: 'foo' }, { s: 'bar' })).toBe(true);
    });

    it('contains: returns false (ok) when string contains value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 's', operator: 'contains', value: 'foo' }, { s: 'foobar' })).toBe(false);
    });

    it('exists: returns true (violated) when property is undefined', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'missing', operator: 'exists' }, {})).toBe(true);
    });

    it('exists: returns false (ok) when property exists', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'x', operator: 'exists' }, { x: 'value' })).toBe(false);
    });
  });

  describe('deployBlueprint()', () => {
    it('throws when blueprint not found', async () => {
      const { svc, db } = makeService();
      db.query.mockResolvedValueOnce({ rows: [] }); // blueprint query returns empty
      await expect(svc.deployBlueprint({ blueprintId: 'missing', targetDeviceIds: [] }))
        .rejects.toThrow('Blueprint not found');
    });

    it('returns deployment results for target devices', async () => {
      const { svc, db, bus } = makeService();
      const bp = { id: 'bp-1', name: 'My Blueprint' };
      const policies = [{ id: 'pol-1', name: 'P1' }];
      db.query
        .mockResolvedValueOnce({ rows: [bp] }) // blueprint query
        .mockResolvedValueOnce({ rows: policies }); // linked policies

      const result = await svc.deployBlueprint({
        blueprintId: 'bp-1',
        targetDeviceIds: ['dev-1', 'dev-2'],
        appliedBy: 'admin',
      });

      expect(result.blueprintId).toBe('bp-1');
      expect(result.results).toHaveLength(2); // 2 devices x 1 policy
      expect(bus.publish).toHaveBeenCalledWith('policy.applied', expect.any(Object));
    });

    it('returns empty results when no target devices and no policies', async () => {
      const { svc, db, bus } = makeService();
      const bp = { id: 'bp-2', name: 'Empty Blueprint' };
      db.query
        .mockResolvedValueOnce({ rows: [bp] })
        .mockResolvedValueOnce({ rows: [] }); // no linked policies

      const result = await svc.deployBlueprint({ blueprintId: 'bp-2', targetDeviceIds: [] });
      expect(result.results).toHaveLength(0);
      expect(bus.publish).toHaveBeenCalledWith('policy.applied', expect.objectContaining({ blueprintId: 'bp-2' }));
    });

    it('includes appliedAt timestamp in result', async () => {
      const { svc, db } = makeService();
      const bp = { id: 'bp-3', name: 'TS Blueprint' };
      db.query
        .mockResolvedValueOnce({ rows: [bp] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await svc.deployBlueprint({ blueprintId: 'bp-3', targetDeviceIds: [] });
      expect(result).toHaveProperty('appliedAt');
      expect(typeof result.appliedAt).toBe('string');
    });
  });

  describe('createPolicy() — additional cases', () => {
    it('returns the inserted row', async () => {
      const { svc, db } = makeService();
      const row = { id: 'pol-2', name: 'Firewall Policy', type: 'firewall' };
      db.query.mockResolvedValue({ rows: [row] });

      const result = await svc.createPolicy({ name: 'Firewall Policy', type: 'firewall' });
      expect(result).toEqual(row);
    });

    it('publishes event with _source = "policy-service"', async () => {
      const { svc, db, bus } = makeService();
      db.query.mockResolvedValue({ rows: [{ id: 'pol-3', name: 'X', type: 'security' }] });

      await svc.createPolicy({ name: 'X', type: 'security' });
      expect(bus.publish).toHaveBeenCalledWith(
        'policy.created',
        expect.objectContaining({ _source: 'policy-service' })
      );
    });

    it('propagates db errors', async () => {
      const { svc, db } = makeService();
      db.query.mockRejectedValue(new Error('DB connection lost'));

      await expect(svc.createPolicy({ name: 'Fail', type: 'security' }))
        .rejects.toThrow('DB connection lost');
    });
  });

  describe('evaluateCompliance() — additional cases', () => {
    it('includes evaluatedAt timestamp in result', async () => {
      const { svc, db } = makeService();
      db.query.mockResolvedValue({ rows: [] });

      const result = await svc.evaluateCompliance({ deviceId: 'dev-x', devicePlatform: 'linux', deviceProperties: {} });
      expect(result).toHaveProperty('evaluatedAt');
      expect(typeof result.evaluatedAt).toBe('string');
    });

    it('includes deviceId in result', async () => {
      const { svc, db } = makeService();
      db.query.mockResolvedValue({ rows: [] });

      const result = await svc.evaluateCompliance({ deviceId: 'dev-unique', devicePlatform: 'macos', deviceProperties: {} });
      expect(result.deviceId).toBe('dev-unique');
    });

    it('handles multiple rules across multiple policies', async () => {
      const { svc, db } = makeService();
      db.query.mockResolvedValue({
        rows: [
          {
            id: 'pol-a',
            name: 'Policy A',
            rules: [
              { key: 'diskEncrypted', operator: 'equals', value: true, severity: 'high' },
              { key: 'osVersion', operator: 'exists', severity: 'medium' },
            ],
          },
          {
            id: 'pol-b',
            name: 'Policy B',
            rules: [{ key: 'firewallEnabled', operator: 'equals', value: true, severity: 'high' }],
          },
        ],
      });

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-multi',
        devicePlatform: 'windows',
        deviceProperties: {
          diskEncrypted: false, // violates
          osVersion: '11',     // ok
          firewallEnabled: false, // violates
        },
      });

      expect(result.isCompliant).toBe(false);
      expect(result.violations).toHaveLength(2);
    });

    it('not_equals: passes when actual !== value', () => {
      const { svc } = makeService();
      // not_equals returns true (violated) when actual === value, false otherwise
      expect(svc._checkRule({ key: 'x', operator: 'not_equals', value: 'blocked' }, { x: 'allowed' })).toBe(false);
    });

    it('greater_than: passes when actual > value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'age', operator: 'greater_than', value: 5 }, { age: 10 })).toBe(false);
    });

    it('less_than: passes when actual < value', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'size', operator: 'less_than', value: 100 }, { size: 50 })).toBe(false);
    });

    it('unknown operator returns false (not violated)', () => {
      const { svc } = makeService();
      expect(svc._checkRule({ key: 'x', operator: 'unknown_op', value: 'y' }, { x: 'z' })).toBe(false);
    });
  });

  describe('_publish() — bus guard', () => {
    it('does not throw when bus.publish throws internally', async () => {
      const { svc, db, bus } = makeService();
      bus.publish.mockImplementation(() => { throw new Error('publish error'); });
      db.query.mockResolvedValue({ rows: [] });

      // evaluateCompliance calls _publish — should not throw
      await expect(
        svc.evaluateCompliance({ deviceId: 'dev-1', devicePlatform: 'all', deviceProperties: {} })
      ).resolves.toBeDefined();
    });
  });
});
