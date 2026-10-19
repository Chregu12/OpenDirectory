'use strict';

const PolicyAggregate = require('../domain/PolicyAggregate');
const {
  POLICY_CREATED, POLICY_UPDATED, POLICY_ENABLED, POLICY_DISABLED,
  POLICY_APPLIED, RULE_ADDED, RULE_REMOVED
} = require('../domain/DomainEvents');

describe('PolicyAggregate', () => {
  const baseData = {
    name: 'Disk Encryption Policy',
    type: 'security',
    platform: 'windows',
  };

  describe('constructor / validation', () => {
    it('creates with defaults', () => {
      const policy = new PolicyAggregate(baseData);
      expect(policy.name).toBe('Disk Encryption Policy');
      expect(policy.type).toBe('security');
      expect(policy.platform).toBe('windows');
      expect(policy.enabled).toBe(true);
      expect(policy.priority).toBe(50);
      expect(policy.rules).toEqual([]);
    });

    it('throws when name is missing', () => {
      expect(() => new PolicyAggregate({ type: 'security' })).toThrow('Policy name is required');
    });

    it('throws when name is empty string', () => {
      expect(() => new PolicyAggregate({ name: '   ', type: 'security' })).toThrow('Policy name is required');
    });

    it('throws when type is missing', () => {
      expect(() => new PolicyAggregate({ name: 'test' })).toThrow('Policy type is required');
    });

    it('throws when data is not an object', () => {
      expect(() => new PolicyAggregate(null)).toThrow('Policy data must be an object');
    });

    it('defaults platform to all', () => {
      const policy = new PolicyAggregate({ name: 'P', type: 'T' });
      expect(policy.platform).toBe('all');
    });

    it('accepts provided priority', () => {
      const policy = new PolicyAggregate({ ...baseData, priority: 99 });
      expect(policy.priority).toBe(99);
    });
  });

  describe('static create()', () => {
    it('creates policy and emits POLICY_CREATED', () => {
      const policy = PolicyAggregate.create({ ...baseData, id: 'pol-1' });
      const events = policy.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(POLICY_CREATED);
      expect(events[0].payload.policyId).toBe('pol-1');
      expect(events[0].payload.name).toBe('Disk Encryption Policy');
    });
  });

  describe('static fromRow()', () => {
    it('reconstitutes from a DB row without emitting events', () => {
      const row = {
        id: 'pol-1', name: 'Test', type: 'security',
        platform: 'all', rules: [], settings: {}, enabled: true,
        priority: 50, created_at: new Date(), updated_at: new Date(),
      };
      const policy = PolicyAggregate.fromRow(row);
      expect(policy.id).toBe('pol-1');
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('update()', () => {
    it('applies allowed changes and emits POLICY_UPDATED', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      policy.update({ name: 'New Name', priority: 99 });
      expect(policy.name).toBe('New Name');
      expect(policy.priority).toBe(99);
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(POLICY_UPDATED);
      expect(events[0].payload.changes).toMatchObject({ name: 'New Name', priority: 99 });
    });

    it('ignores disallowed fields', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      policy.update({ rules: [{ type: 'x' }], enabled: false });
      expect(policy.rules).toEqual([]); // rules not in allowed list
    });
  });

  describe('enable() / disable()', () => {
    it('enable() emits POLICY_ENABLED and sets enabled=true', () => {
      const policy = new PolicyAggregate({ ...baseData, enabled: false });
      policy.enable();
      expect(policy.enabled).toBe(true);
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(POLICY_ENABLED);
    });

    it('enable() is idempotent — no event if already enabled', () => {
      const policy = new PolicyAggregate({ ...baseData, enabled: true });
      policy.enable();
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('disable() emits POLICY_DISABLED and sets enabled=false', () => {
      const policy = new PolicyAggregate({ ...baseData, enabled: true });
      policy.disable();
      expect(policy.enabled).toBe(false);
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(POLICY_DISABLED);
    });

    it('disable() is idempotent — no event if already disabled', () => {
      const policy = new PolicyAggregate({ ...baseData, enabled: false });
      policy.disable();
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('addRule()', () => {
    it('adds a rule and emits RULE_ADDED', () => {
      const policy = new PolicyAggregate(baseData);
      const rule = { type: 'disk-encryption', operator: 'equals', value: true };
      policy.addRule(rule);
      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0]).toEqual(rule);
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(RULE_ADDED);
    });

    it('throws when rule has no type', () => {
      const policy = new PolicyAggregate(baseData);
      expect(() => policy.addRule({ operator: 'equals' })).toThrow('Rule must have a type');
    });

    it('throws when rule is null', () => {
      const policy = new PolicyAggregate(baseData);
      expect(() => policy.addRule(null)).toThrow('Rule must have a type');
    });
  });

  describe('removeRule()', () => {
    it('removes rule by index and emits RULE_REMOVED', () => {
      const policy = new PolicyAggregate({ ...baseData, rules: [{ type: 'r1' }, { type: 'r2' }] });
      policy.removeRule(0);
      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0]).toEqual({ type: 'r2' });
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(RULE_REMOVED);
      expect(events[0].payload.removed).toEqual({ type: 'r1' });
    });

    it('throws for out-of-bounds index', () => {
      const policy = new PolicyAggregate({ ...baseData, rules: [{ type: 'r1' }] });
      expect(() => policy.removeRule(5)).toThrow('out of bounds');
    });

    it('throws for negative index', () => {
      const policy = new PolicyAggregate({ ...baseData, rules: [{ type: 'r1' }] });
      expect(() => policy.removeRule(-1)).toThrow('out of bounds');
    });
  });

  describe('markApplied()', () => {
    it('emits POLICY_APPLIED with target', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      policy.markApplied('device-abc');
      const events = policy.getAndClearDomainEvents();
      expect(events[0].type).toBe(POLICY_APPLIED);
      expect(events[0].payload.target).toBe('device-abc');
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('returns events then clears them', () => {
      const policy = PolicyAggregate.create({ ...baseData, id: 'pol-1' });
      const events = policy.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('toJSON()', () => {
    it('returns plain serialisable object', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      const json = policy.toJSON();
      expect(json).toMatchObject({ id: 'pol-1', name: 'Disk Encryption Policy', type: 'security' });
      expect(json.createdAt).toBeInstanceOf(Date);
    });

    it('includes all expected fields', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1', priority: 77, settings: { foo: 'bar' } });
      const json = policy.toJSON();
      expect(json).toHaveProperty('id', 'pol-1');
      expect(json).toHaveProperty('name');
      expect(json).toHaveProperty('type');
      expect(json).toHaveProperty('platform');
      expect(json).toHaveProperty('rules');
      expect(json).toHaveProperty('settings');
      expect(json).toHaveProperty('enabled');
      expect(json).toHaveProperty('priority', 77);
      expect(json).toHaveProperty('createdAt');
      expect(json).toHaveProperty('updatedAt');
      expect(Array.isArray(json.rules)).toBe(true);
    });
  });

  describe('fromRow() — DB row reconstruction', () => {
    it('maps snake_case created_at / updated_at to camelCase', () => {
      const now = new Date('2024-01-15T10:00:00Z');
      const row = {
        id: 'pol-db-1', name: 'DB Policy', type: 'compliance',
        platform: 'linux', rules: [], settings: {}, enabled: false,
        priority: 20, created_at: now, updated_at: now,
      };
      const policy = PolicyAggregate.fromRow(row);
      expect(policy.createdAt).toEqual(now);
      expect(policy.updatedAt).toEqual(now);
      expect(policy.enabled).toBe(false);
      expect(policy.priority).toBe(20);
    });

    it('also accepts camelCase dates from row', () => {
      const now = new Date();
      const row = {
        id: 'pol-db-2', name: 'CamelRow', type: 'security',
        platform: 'all', rules: [], settings: {}, enabled: true,
        priority: 50, createdAt: now, updatedAt: now,
      };
      const policy = PolicyAggregate.fromRow(row);
      expect(policy.createdAt).toEqual(now);
    });

    it('does not emit any domain events', () => {
      const row = {
        id: 'pol-db-3', name: 'No Events', type: 'network',
        platform: 'all', rules: [], settings: {}, enabled: true,
        priority: 50, created_at: new Date(), updated_at: new Date(),
      };
      const policy = PolicyAggregate.fromRow(row);
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('update() — edge cases', () => {
    it('emits POLICY_UPDATED even for empty allowed changes (always records update)', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      policy.update({});
      const events = policy.getAndClearDomainEvents();
      // update() always emits regardless of whether any fields changed
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(POLICY_UPDATED);
    });

    it('does not apply unknown fields', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1' });
      policy.update({ malicious: true, __proto__: 'x' });
      expect((policy)['malicious']).toBeUndefined();
    });

    it('partial update preserves untouched fields', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1', priority: 10 });
      policy.update({ name: 'Only Name Changed' });
      expect(policy.priority).toBe(10);
      expect(policy.type).toBe('security');
    });
  });

  describe('event accumulation and clearing', () => {
    it('multiple state transitions accumulate events and clearAll at once', () => {
      const policy = new PolicyAggregate({ ...baseData, id: 'pol-1', enabled: false });
      // enable → disable → enable
      policy.enable();   // POLICY_ENABLED
      policy.disable();  // POLICY_DISABLED
      policy.enable();   // POLICY_ENABLED

      const events = policy.getAndClearDomainEvents();
      expect(events).toHaveLength(3);
      expect(events[0].type).toBe(POLICY_ENABLED);
      expect(events[1].type).toBe(POLICY_DISABLED);
      expect(events[2].type).toBe(POLICY_ENABLED);

      // cleared now
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('each domain event has type, payload, and occurredAt', () => {
      const policy = PolicyAggregate.create({ ...baseData, id: 'pol-1' });
      const [event] = policy.getAndClearDomainEvents();
      expect(event).toHaveProperty('type');
      expect(event).toHaveProperty('payload');
      expect(event).toHaveProperty('occurredAt');
      expect(event.occurredAt).toBeInstanceOf(Date);
    });
  });
});
