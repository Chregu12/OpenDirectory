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
} = {}) {
  return {
    id,
    name,
    type,
    platform,
    enabled,
    status,
    enable: jest.fn(),
    disable: jest.fn(),
    update: jest.fn(),
    getAndClearDomainEvents: jest.fn().mockReturnValue([]),
    toJSON: jest.fn().mockReturnValue({ id, name, type, platform, enabled, status }),
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
});
