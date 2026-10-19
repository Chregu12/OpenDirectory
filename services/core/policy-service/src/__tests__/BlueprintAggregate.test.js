'use strict';

const BlueprintAggregate = require('../domain/BlueprintAggregate');
const {
  BLUEPRINT_CREATED, BLUEPRINT_UPDATED, BLUEPRINT_DEPLOYED
} = require('../domain/DomainEvents');

describe('BlueprintAggregate', () => {
  const baseData = {
    name: 'Standard Windows Blueprint',
    platform: 'windows',
  };

  describe('constructor / validation', () => {
    it('creates with defaults', () => {
      const bp = new BlueprintAggregate(baseData);
      expect(bp.name).toBe('Standard Windows Blueprint');
      expect(bp.platform).toBe('windows');
      expect(bp.version).toBe(1);
      expect(bp.policies).toEqual([]);
      expect(bp.description).toBe('');
    });

    it('throws when name is missing', () => {
      expect(() => new BlueprintAggregate({ platform: 'all' })).toThrow('Blueprint name is required');
    });

    it('throws when name is empty string', () => {
      expect(() => new BlueprintAggregate({ name: '' })).toThrow('Blueprint name is required');
    });

    it('throws when data is null', () => {
      expect(() => new BlueprintAggregate(null)).toThrow('Blueprint data must be an object');
    });

    it('defaults platform to all', () => {
      const bp = new BlueprintAggregate({ name: 'Test' });
      expect(bp.platform).toBe('all');
    });
  });

  describe('static create()', () => {
    it('emits BLUEPRINT_CREATED', () => {
      const bp = BlueprintAggregate.create({ ...baseData, id: 'bp-1' });
      const events = bp.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(BLUEPRINT_CREATED);
      expect(events[0].payload.blueprintId).toBe('bp-1');
      expect(events[0].payload.name).toBe('Standard Windows Blueprint');
    });
  });

  describe('static fromRow()', () => {
    it('reconstitutes from a DB row without events', () => {
      const row = {
        id: 'bp-1', name: 'Test', description: 'desc', platform: 'all',
        policies: [], settings: {}, version: 3, created_at: new Date(), updated_at: new Date(),
      };
      const bp = BlueprintAggregate.fromRow(row);
      expect(bp.id).toBe('bp-1');
      expect(bp.version).toBe(3);
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('update()', () => {
    it('applies allowed fields, bumps version, emits BLUEPRINT_UPDATED', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.update({ name: 'New Name', description: 'Updated' });
      expect(bp.name).toBe('New Name');
      expect(bp.description).toBe('Updated');
      expect(bp.version).toBe(2);
      const events = bp.getAndClearDomainEvents();
      expect(events[0].type).toBe(BLUEPRINT_UPDATED);
      expect(events[0].payload.version).toBe(2);
    });

    it('ignores disallowed fields', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', version: 1 });
      bp.update({ policies: ['pol-1'], version: 99 });
      expect(bp.policies).toEqual([]); // not in allowed list
      expect(bp.version).toBe(2);     // bumped, not set to 99
    });
  });

  describe('addPolicy()', () => {
    it('adds policy id and bumps version', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.addPolicy('pol-1');
      expect(bp.policies).toContain('pol-1');
      expect(bp.version).toBe(2);
      const events = bp.getAndClearDomainEvents();
      expect(events[0].type).toBe(BLUEPRINT_UPDATED);
      expect(events[0].payload.changes.addedPolicy).toBe('pol-1');
    });

    it('is idempotent — does not duplicate', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', policies: ['pol-1'] });
      bp.addPolicy('pol-1');
      expect(bp.policies).toHaveLength(1);
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('throws when policyId is falsy', () => {
      const bp = new BlueprintAggregate(baseData);
      expect(() => bp.addPolicy(null)).toThrow('policyId is required');
      expect(() => bp.addPolicy('')).toThrow('policyId is required');
    });
  });

  describe('removePolicy()', () => {
    it('removes policy id and bumps version', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', policies: ['pol-1', 'pol-2'] });
      bp.removePolicy('pol-1');
      expect(bp.policies).toEqual(['pol-2']);
      expect(bp.version).toBe(2);
      const events = bp.getAndClearDomainEvents();
      expect(events[0].type).toBe(BLUEPRINT_UPDATED);
    });

    it('is idempotent — no event if policy not present', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', policies: [] });
      bp.removePolicy('pol-x');
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('deploy()', () => {
    it('emits BLUEPRINT_DEPLOYED with target and deployedBy', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.deploy('device-abc', 'admin-user');
      const events = bp.getAndClearDomainEvents();
      expect(events[0].type).toBe(BLUEPRINT_DEPLOYED);
      expect(events[0].payload.target).toBe('device-abc');
      expect(events[0].payload.deployedBy).toBe('admin-user');
    });

    it('defaults deployedBy to system', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.deploy('*');
      const [event] = bp.getAndClearDomainEvents();
      expect(event.payload.deployedBy).toBe('system');
    });

    it('throws when target is falsy', () => {
      const bp = new BlueprintAggregate(baseData);
      expect(() => bp.deploy('')).toThrow('Deploy target is required');
      expect(() => bp.deploy(null)).toThrow('Deploy target is required');
    });
  });

  describe('getAndClearDomainEvents()', () => {
    it('returns events then clears them', () => {
      const bp = BlueprintAggregate.create({ ...baseData, id: 'bp-1' });
      const events = bp.getAndClearDomainEvents();
      expect(events).toHaveLength(1);
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('toJSON()', () => {
    it('returns plain serialisable object', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      const json = bp.toJSON();
      expect(json).toMatchObject({ id: 'bp-1', name: 'Standard Windows Blueprint' });
      expect(json.createdAt).toBeInstanceOf(Date);
    });

    it('includes all expected fields with correct shapes', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', description: 'A description', policies: ['pol-1'], version: 2, settings: { key: 'val' } });
      const json = bp.toJSON();
      expect(json).toHaveProperty('id', 'bp-1');
      expect(json).toHaveProperty('name', 'Standard Windows Blueprint');
      expect(json).toHaveProperty('description', 'A description');
      expect(json).toHaveProperty('platform', 'windows');
      expect(json).toHaveProperty('policies');
      expect(Array.isArray(json.policies)).toBe(true);
      expect(json.policies).toContain('pol-1');
      expect(json).toHaveProperty('settings');
      expect(json).toHaveProperty('version', 2);
      expect(json).toHaveProperty('createdAt');
      expect(json).toHaveProperty('updatedAt');
      expect(json.createdAt).toBeInstanceOf(Date);
      expect(json.updatedAt).toBeInstanceOf(Date);
    });

    it('does not expose internal _domainEvents', () => {
      const bp = BlueprintAggregate.create({ ...baseData, id: 'bp-1' });
      const json = bp.toJSON();
      expect(json).not.toHaveProperty('_domainEvents');
    });
  });

  describe('fromRow() — DB row reconstruction', () => {
    it('maps snake_case created_at / updated_at to camelCase', () => {
      const now = new Date('2024-03-01T08:00:00Z');
      const row = {
        id: 'bp-db-1', name: 'DB Blueprint', description: 'From DB',
        platform: 'macos', policies: ['pol-a'], settings: {}, version: 5,
        created_at: now, updated_at: now,
      };
      const bp = BlueprintAggregate.fromRow(row);
      expect(bp.id).toBe('bp-db-1');
      expect(bp.version).toBe(5);
      expect(bp.createdAt).toEqual(now);
      expect(bp.updatedAt).toEqual(now);
      expect(bp.policies).toEqual(['pol-a']);
    });

    it('also accepts camelCase dates', () => {
      const now = new Date();
      const row = {
        id: 'bp-db-2', name: 'Camel Blueprint', platform: 'all',
        policies: [], settings: {}, version: 1, createdAt: now, updatedAt: now,
      };
      const bp = BlueprintAggregate.fromRow(row);
      expect(bp.createdAt).toEqual(now);
    });

    it('emits no domain events on reconstruction', () => {
      const row = {
        id: 'bp-db-3', name: 'No Events BP', platform: 'windows',
        policies: [], settings: {}, version: 1,
        created_at: new Date(), updated_at: new Date(),
      };
      const bp = BlueprintAggregate.fromRow(row);
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });
  });

  describe('update() — edge cases', () => {
    it('does not apply unknown fields', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.update({ policies: ['pol-x'], version: 99, unknown: true });
      expect(bp.policies).toEqual([]);  // not in allowed list
      expect((bp)['unknown']).toBeUndefined();
    });

    it('partial update only changes supplied fields', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1', description: 'Original' });
      bp.update({ name: 'New Name' });
      expect(bp.description).toBe('Original');
      expect(bp.name).toBe('New Name');
    });
  });

  describe('event accumulation', () => {
    it('events accumulate across multiple operations and clear together', () => {
      const bp = new BlueprintAggregate({ ...baseData, id: 'bp-1' });
      bp.addPolicy('pol-1');    // BLUEPRINT_UPDATED
      bp.addPolicy('pol-2');    // BLUEPRINT_UPDATED
      bp.removePolicy('pol-1'); // BLUEPRINT_UPDATED

      const events = bp.getAndClearDomainEvents();
      expect(events).toHaveLength(3);
      events.forEach(ev => expect(ev.type).toBe(BLUEPRINT_UPDATED));
      // cleared
      expect(bp.getAndClearDomainEvents()).toHaveLength(0);
    });

    it('each event has type, payload, and occurredAt', () => {
      const bp = BlueprintAggregate.create({ ...baseData, id: 'bp-1' });
      const [event] = bp.getAndClearDomainEvents();
      expect(event).toHaveProperty('type', BLUEPRINT_CREATED);
      expect(event).toHaveProperty('payload');
      expect(event).toHaveProperty('occurredAt');
      expect(event.occurredAt).toBeInstanceOf(Date);
    });
  });
});
