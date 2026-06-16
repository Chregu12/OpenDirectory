'use strict';

const PolicyAggregate = require('../PolicyAggregate');
const {
  POLICY_CREATED,
  POLICY_ENABLED,
  POLICY_DISABLED,
  POLICY_UPDATED,
  RULE_ADDED,
  RULE_REMOVED,
  POLICY_APPLIED
} = require('../DomainEvents');

describe('PolicyAggregate', () => {
  const validProps = {
    id:       'policy-1',
    name:     'Default Password Policy',
    type:     'password',
    platform: 'all',
    enabled:  false
  };

  // ── create() ───────────────────────────────────────────────────────────────

  describe('create()', () => {
    it('returns a PolicyAggregate with the correct fields', () => {
      const policy = PolicyAggregate.create(validProps);

      expect(policy).toBeInstanceOf(PolicyAggregate);
      expect(policy.id).toBe('policy-1');
      expect(policy.name).toBe('Default Password Policy');
      expect(policy.type).toBe('password');
      expect(policy.platform).toBe('all');
    });

    it('emits a POLICY_CREATED event with occurredAt', () => {
      const policy = PolicyAggregate.create(validProps);
      const events = policy.getAndClearDomainEvents();

      expect(events).toHaveLength(1);
      const [evt] = events;
      expect(evt.type).toBe(POLICY_CREATED);
      expect(evt.occurredAt).toBeInstanceOf(Date);
      expect(evt.payload.policyId).toBe('policy-1');
      expect(evt.payload.name).toBe('Default Password Policy');
    });

    it('defaults enabled to true when not specified', () => {
      const policy = PolicyAggregate.create({ name: 'P', type: 'compliance' });
      expect(policy.enabled).toBe(true);
    });

    it('throws when name is missing', () => {
      expect(() => PolicyAggregate.create({ type: 'compliance' })).toThrow('name');
    });

    it('throws when type is missing', () => {
      expect(() => PolicyAggregate.create({ name: 'P' })).toThrow('type');
    });
  });

  // ── enable() ───────────────────────────────────────────────────────────────

  describe('enable()', () => {
    it('sets enabled to true and emits POLICY_ENABLED', () => {
      // Create with enabled:false so enable() is not a no-op
      const policy = PolicyAggregate.create({ ...validProps, enabled: false });
      policy.getAndClearDomainEvents();

      policy.enable();

      expect(policy.enabled).toBe(true);

      const events = policy.getAndClearDomainEvents();
      const evt = events.find(e => e.type === POLICY_ENABLED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
    });

    it('is idempotent — calling enable() on an already-enabled policy produces no event', () => {
      const policy = PolicyAggregate.create({ name: 'P', type: 'T', enabled: true });
      policy.getAndClearDomainEvents();

      policy.enable();
      const events = policy.getAndClearDomainEvents();
      expect(events.some(e => e.type === POLICY_ENABLED)).toBe(false);
    });
  });

  // ── disable() ──────────────────────────────────────────────────────────────

  describe('disable()', () => {
    it('sets enabled to false and emits POLICY_DISABLED', () => {
      const policy = PolicyAggregate.create({ name: 'P', type: 'T', enabled: true });
      policy.getAndClearDomainEvents();

      policy.disable();

      expect(policy.enabled).toBe(false);

      const events = policy.getAndClearDomainEvents();
      const evt = events.find(e => e.type === POLICY_DISABLED);
      expect(evt).toBeDefined();
      expect(evt.occurredAt).toBeInstanceOf(Date);
    });

    it('is idempotent — calling disable() on an already-disabled policy produces no event', () => {
      const policy = PolicyAggregate.create({ ...validProps, enabled: false });
      policy.getAndClearDomainEvents();

      policy.disable();
      const events = policy.getAndClearDomainEvents();
      expect(events.some(e => e.type === POLICY_DISABLED)).toBe(false);
    });
  });

  // ── update() ───────────────────────────────────────────────────────────────

  describe('update()', () => {
    it('updates mutable fields and emits POLICY_UPDATED', () => {
      const policy = PolicyAggregate.create(validProps);
      policy.getAndClearDomainEvents();

      policy.update({ name: 'Renamed Policy', priority: 10 });

      expect(policy.name).toBe('Renamed Policy');
      expect(policy.priority).toBe(10);

      const events = policy.getAndClearDomainEvents();
      const evt = events.find(e => e.type === POLICY_UPDATED);
      expect(evt).toBeDefined();
    });
  });

  // ── addRule() / removeRule() ────────────────────────────────────────────────

  describe('addRule()', () => {
    it('appends a rule and emits RULE_ADDED', () => {
      const policy = PolicyAggregate.create(validProps);
      policy.getAndClearDomainEvents();

      policy.addRule({ type: 'min-length', value: 12 });

      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0]).toEqual({ type: 'min-length', value: 12 });

      const events = policy.getAndClearDomainEvents();
      expect(events.some(e => e.type === RULE_ADDED)).toBe(true);
    });

    it('throws when rule has no type', () => {
      const policy = PolicyAggregate.create(validProps);
      expect(() => policy.addRule({ value: 10 })).toThrow();
    });
  });

  describe('removeRule()', () => {
    it('removes a rule by index and emits RULE_REMOVED', () => {
      const policy = PolicyAggregate.create(validProps);
      policy.addRule({ type: 'min-length', value: 8 });
      policy.addRule({ type: 'complexity', value: true });
      policy.getAndClearDomainEvents();

      policy.removeRule(0);

      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0].type).toBe('complexity');

      const events = policy.getAndClearDomainEvents();
      expect(events.some(e => e.type === RULE_REMOVED)).toBe(true);
    });

    it('throws when index is out of bounds', () => {
      const policy = PolicyAggregate.create(validProps);
      expect(() => policy.removeRule(99)).toThrow();
    });
  });

  // ── markApplied() ──────────────────────────────────────────────────────────

  describe('markApplied()', () => {
    it('emits a POLICY_APPLIED event with target', () => {
      const policy = PolicyAggregate.create(validProps);
      policy.getAndClearDomainEvents();

      policy.markApplied('device-group-A');
      const events = policy.getAndClearDomainEvents();

      const evt = events.find(e => e.type === POLICY_APPLIED);
      expect(evt).toBeDefined();
      expect(evt.payload.target).toBe('device-group-A');
    });
  });

  // ── getAndClearDomainEvents() ──────────────────────────────────────────────

  describe('getAndClearDomainEvents()', () => {
    it('returns events and clears them — subsequent call returns []', () => {
      const policy = PolicyAggregate.create(validProps);

      const firstCall = policy.getAndClearDomainEvents();
      expect(firstCall.length).toBeGreaterThan(0);

      const secondCall = policy.getAndClearDomainEvents();
      expect(secondCall).toHaveLength(0);
    });

    it('accumulates events across multiple commands before returning', () => {
      const policy = PolicyAggregate.create({ name: 'P', type: 'T', enabled: false });
      policy.getAndClearDomainEvents(); // clear create event

      policy.enable();
      policy.disable();
      policy.addRule({ type: 'x' });

      const events = policy.getAndClearDomainEvents();
      const types = events.map(e => e.type);

      expect(types).toContain(POLICY_ENABLED);
      expect(types).toContain(POLICY_DISABLED);
      expect(types).toContain(RULE_ADDED);

      // Cleared after retrieval
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  // ── fromRow() ──────────────────────────────────────────────────────────────

  describe('fromRow()', () => {
    it('reconstitutes a policy without emitting a domain event', () => {
      const policy = PolicyAggregate.fromRow({
        id:       'policy-2',
        name:     'Screen Lock',
        type:     'security',
        platform: 'macos',
        rules:    [],
        settings: {},
        enabled:  true,
        priority: 80
      });

      expect(policy.id).toBe('policy-2');
      expect(policy.enabled).toBe(true);
      expect(policy.getAndClearDomainEvents()).toHaveLength(0);
    });
  });
});
