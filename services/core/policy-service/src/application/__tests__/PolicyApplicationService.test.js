'use strict';

const PolicyApplicationService = require('../PolicyApplicationService');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePolicy({
  id = 'pol-1',
  name = 'Test Policy',
  type = 'security',
  platform = 'all',
  enabled = false,
  status = 'draft',
  rules = [],
} = {}) {
  return {
    id,
    name,
    type,
    platform,
    enabled,
    status,
    rules,
    enable: jest.fn(),
    disable: jest.fn(),
    update: jest.fn(),
    getAndClearDomainEvents: jest.fn().mockReturnValue([]),
    toJSON: jest.fn().mockReturnValue({ id, name, type, platform, enabled, status, rules }),
  };
}

// ---------------------------------------------------------------------------
// Mock repositories & bus
// ---------------------------------------------------------------------------

const mockPolicyRepo = {
  findAll: jest.fn(),
  findById: jest.fn(),
  findActive: jest.fn(),
  save: jest.fn(),
  delete: jest.fn(),
  activate: jest.fn(),
  deactivate: jest.fn(),
};

const mockBus = {
  publish: jest.fn(),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PolicyApplicationService', () => {
  let svc;

  beforeEach(() => {
    jest.clearAllMocks();

    svc = new PolicyApplicationService({
      policyRepository: mockPolicyRepo,
      messageBus: mockBus,
      logger: { warn: jest.fn(), info: jest.fn(), error: jest.fn() },
    });
  });

  // ── constructor guard ──────────────────────────────────────────────────────

  it('throws when policyRepository is not provided', () => {
    expect(() => new PolicyApplicationService({})).toThrow('policyRepository is required');
  });

  // ── createPolicy ───────────────────────────────────────────────────────────

  describe('createPolicy()', () => {
    it('saves via repo and returns a plain policy object', async () => {
      const saved = makePolicy();
      mockPolicyRepo.save.mockResolvedValue(saved);

      const result = await svc.createPolicy({ name: 'New Policy', type: 'security' });

      expect(mockPolicyRepo.save).toHaveBeenCalledTimes(1);
      // The argument passed to save is a PolicyAggregate instance
      const savedArg = mockPolicyRepo.save.mock.calls[0][0];
      expect(savedArg.name).toBe('New Policy');
      expect(savedArg.type).toBe('security');

      expect(result).toEqual(saved.toJSON());
    });

    it('throws a validation error when name is missing', async () => {
      await expect(
        svc.createPolicy({ type: 'security' })
      ).rejects.toThrow('Policy name is required');

      expect(mockPolicyRepo.save).not.toHaveBeenCalled();
    });

    it('throws a validation error when type is missing', async () => {
      await expect(
        svc.createPolicy({ name: 'My Policy' })
      ).rejects.toThrow('Policy type is required');

      expect(mockPolicyRepo.save).not.toHaveBeenCalled();
    });

    it('propagates repository errors', async () => {
      mockPolicyRepo.save.mockRejectedValue(new Error('DB connection lost'));

      await expect(
        svc.createPolicy({ name: 'Fail', type: 'security' })
      ).rejects.toThrow('DB connection lost');
    });
  });

  // ── getPolicy ──────────────────────────────────────────────────────────────

  describe('getPolicy()', () => {
    it('calls findById and returns the serialised policy', async () => {
      const policy = makePolicy({ id: 'pol-42' });
      mockPolicyRepo.findById.mockResolvedValue(policy);

      const result = await svc.getPolicy('pol-42');

      expect(mockPolicyRepo.findById).toHaveBeenCalledWith('pol-42');
      expect(result).toEqual(policy.toJSON());
    });

    it('returns null when policy does not exist', async () => {
      mockPolicyRepo.findById.mockResolvedValue(null);

      const result = await svc.getPolicy('non-existent');

      expect(result).toBeNull();
    });
  });

  // ── updatePolicy ───────────────────────────────────────────────────────────

  describe('updatePolicy()', () => {
    it('loads, updates, and saves the policy, returning a plain object', async () => {
      const policy = makePolicy({ id: 'pol-1' });
      const updated = makePolicy({ id: 'pol-1', name: 'Updated Name' });
      mockPolicyRepo.findById.mockResolvedValue(policy);
      mockPolicyRepo.save.mockResolvedValue(updated);

      const result = await svc.updatePolicy('pol-1', { name: 'Updated Name' });

      expect(mockPolicyRepo.findById).toHaveBeenCalledWith('pol-1');
      expect(policy.update).toHaveBeenCalledWith({ name: 'Updated Name' });
      expect(mockPolicyRepo.save).toHaveBeenCalledWith(policy);
      expect(result).toEqual(updated.toJSON());
    });

    it('throws 404 when policy is not found', async () => {
      mockPolicyRepo.findById.mockResolvedValue(null);

      await expect(
        svc.updatePolicy('missing', { name: 'X' })
      ).rejects.toMatchObject({ message: 'Policy not found', statusCode: 404 });

      expect(mockPolicyRepo.save).not.toHaveBeenCalled();
    });
  });

  // ── deletePolicy ───────────────────────────────────────────────────────────

  describe('deletePolicy()', () => {
    it('calls policyRepo.delete and returns true', async () => {
      mockPolicyRepo.delete.mockResolvedValue(true);

      const result = await svc.deletePolicy('pol-1');

      expect(mockPolicyRepo.delete).toHaveBeenCalledWith('pol-1');
      expect(result).toBe(true);
    });

    it('throws 404 when the policy does not exist', async () => {
      mockPolicyRepo.delete.mockResolvedValue(false);

      await expect(svc.deletePolicy('missing')).rejects.toMatchObject({
        message: 'Policy not found',
        statusCode: 404,
      });
    });
  });

  // ── activatePolicy ─────────────────────────────────────────────────────────

  describe('activatePolicy()', () => {
    it('calls policyRepo.activate and enables the policy', async () => {
      const policy = makePolicy({ id: 'pol-1', enabled: false });
      mockPolicyRepo.activate.mockResolvedValue(policy);

      const result = await svc.activatePolicy('pol-1');

      expect(mockPolicyRepo.activate).toHaveBeenCalledWith('pol-1');
      expect(policy.enable).toHaveBeenCalled();
      expect(result).toEqual(policy.toJSON());
    });

    it('throws 404 when policy does not exist', async () => {
      mockPolicyRepo.activate.mockResolvedValue(null);

      await expect(svc.activatePolicy('missing')).rejects.toMatchObject({
        message: 'Policy not found',
        statusCode: 404,
      });
    });
  });

  // ── evaluateCompliance ─────────────────────────────────────────────────────

  describe('evaluateCompliance()', () => {
    it('returns compliant when there are no active policies', async () => {
      mockPolicyRepo.findActive.mockResolvedValue([]);

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-1',
        devicePlatform: 'windows',
        deviceProperties: {},
      });

      expect(result.isCompliant).toBe(true);
      expect(result.violations).toEqual([]);
      expect(mockBus.publish).toHaveBeenCalledWith('device.compliant', expect.objectContaining({ deviceId: 'dev-1' }));
    });

    it('returns non-compliant when a rule is violated', async () => {
      const policy = makePolicy({
        id: 'pol-1',
        name: 'Encryption Check',
        rules: [{ key: 'diskEncrypted', operator: 'equals', value: true, severity: 'high' }],
      });
      mockPolicyRepo.findActive.mockResolvedValue([policy]);

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-1',
        devicePlatform: 'windows',
        deviceProperties: { diskEncrypted: false }, // violates equals:true
      });

      expect(result.isCompliant).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(mockBus.publish).toHaveBeenCalledWith('device.non_compliant', expect.objectContaining({ deviceId: 'dev-1' }));
    });

    it('handles multiple rules across multiple policies', async () => {
      const policyA = makePolicy({
        id: 'pol-a',
        name: 'Policy A',
        rules: [
          { key: 'diskEncrypted', operator: 'equals', value: true, severity: 'high' },
          { key: 'osVersion', operator: 'exists', severity: 'medium' },
        ],
      });
      const policyB = makePolicy({
        id: 'pol-b',
        name: 'Policy B',
        rules: [{ key: 'firewallEnabled', operator: 'equals', value: true, severity: 'high' }],
      });
      mockPolicyRepo.findActive.mockResolvedValue([policyA, policyB]);

      const result = await svc.evaluateCompliance({
        deviceId: 'dev-multi',
        devicePlatform: 'windows',
        deviceProperties: {
          diskEncrypted: false,   // violates
          osVersion: '11',        // ok
          firewallEnabled: false, // violates
        },
      });

      expect(result.isCompliant).toBe(false);
      expect(result.violations).toHaveLength(2);
    });

    it('includes deviceId and evaluatedAt timestamp in the result', async () => {
      mockPolicyRepo.findActive.mockResolvedValue([]);

      const result = await svc.evaluateCompliance({ deviceId: 'dev-unique', devicePlatform: 'linux', deviceProperties: {} });

      expect(result.deviceId).toBe('dev-unique');
      expect(result).toHaveProperty('evaluatedAt');
      expect(typeof result.evaluatedAt).toBe('string');
    });

    it('does not throw when bus.publish throws internally', async () => {
      mockPolicyRepo.findActive.mockResolvedValue([]);
      mockBus.publish.mockImplementationOnce(() => { throw new Error('publish error'); });

      await expect(
        svc.evaluateCompliance({ deviceId: 'dev-1', devicePlatform: 'all', deviceProperties: {} })
      ).resolves.toBeDefined();
    });
  });

  // ── _checkRule ─────────────────────────────────────────────────────────────

  describe('_checkRule()', () => {
    it('returns false when rule has no key', () => {
      expect(svc._checkRule({}, {})).toBe(false);
    });

    it('equals: returns true (violated) when actual !== value', () => {
      expect(svc._checkRule({ key: 'x', operator: 'equals', value: true }, { x: false })).toBe(true);
    });

    it('equals: returns false (ok) when actual === value', () => {
      expect(svc._checkRule({ key: 'x', operator: 'equals', value: true }, { x: true })).toBe(false);
    });

    it('not_equals: returns true (violated) when actual === value', () => {
      expect(svc._checkRule({ key: 'x', operator: 'not_equals', value: 'blocked' }, { x: 'blocked' })).toBe(true);
    });

    it('not_equals: passes when actual !== value', () => {
      expect(svc._checkRule({ key: 'x', operator: 'not_equals', value: 'blocked' }, { x: 'allowed' })).toBe(false);
    });

    it('greater_than: returns true (violated) when actual <= value', () => {
      expect(svc._checkRule({ key: 'age', operator: 'greater_than', value: 5 }, { age: 3 })).toBe(true);
    });

    it('greater_than: passes when actual > value', () => {
      expect(svc._checkRule({ key: 'age', operator: 'greater_than', value: 5 }, { age: 10 })).toBe(false);
    });

    it('less_than: returns true (violated) when actual >= value', () => {
      expect(svc._checkRule({ key: 'size', operator: 'less_than', value: 10 }, { size: 15 })).toBe(true);
    });

    it('less_than: passes when actual < value', () => {
      expect(svc._checkRule({ key: 'size', operator: 'less_than', value: 100 }, { size: 50 })).toBe(false);
    });

    it('contains: returns true (violated) when string does not contain value', () => {
      expect(svc._checkRule({ key: 's', operator: 'contains', value: 'foo' }, { s: 'bar' })).toBe(true);
    });

    it('contains: returns false (ok) when string contains value', () => {
      expect(svc._checkRule({ key: 's', operator: 'contains', value: 'foo' }, { s: 'foobar' })).toBe(false);
    });

    it('exists: returns true (violated) when property is undefined', () => {
      expect(svc._checkRule({ key: 'missing', operator: 'exists' }, {})).toBe(true);
    });

    it('exists: returns false (ok) when property exists', () => {
      expect(svc._checkRule({ key: 'x', operator: 'exists' }, { x: 'value' })).toBe(false);
    });

    it('unknown operator returns false (not violated)', () => {
      expect(svc._checkRule({ key: 'x', operator: 'unknown_op', value: 'y' }, { x: 'z' })).toBe(false);
    });
  });
});
