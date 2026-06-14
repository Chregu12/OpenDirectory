'use strict';

const DomainEvents = require('../domain/DomainEvents');

describe('DomainEvents', () => {
  describe('exports', () => {
    it('exports an object', () => {
      expect(typeof DomainEvents).toBe('object');
      expect(DomainEvents).not.toBeNull();
    });

    const expectedEvents = [
      'POLICY_CREATED',
      'POLICY_UPDATED',
      'POLICY_ENABLED',
      'POLICY_DISABLED',
      'POLICY_DELETED',
      'POLICY_APPLIED',
      'RULE_ADDED',
      'RULE_REMOVED',
      'BLUEPRINT_CREATED',
      'BLUEPRINT_UPDATED',
      'BLUEPRINT_DEPLOYED',
      'BLUEPRINT_DELETED',
    ];

    for (const name of expectedEvents) {
      it(`exports ${name} as a non-empty string`, () => {
        expect(DomainEvents).toHaveProperty(name);
        expect(typeof DomainEvents[name]).toBe('string');
        expect(DomainEvents[name].trim().length).toBeGreaterThan(0);
      });
    }

    it('all exported event values are unique', () => {
      const values = Object.values(DomainEvents);
      const unique = new Set(values);
      expect(unique.size).toBe(values.length);
    });

    it('POLICY_CREATED equals "PolicyCreated"', () => {
      expect(DomainEvents.POLICY_CREATED).toBe('PolicyCreated');
    });

    it('POLICY_UPDATED equals "PolicyUpdated"', () => {
      expect(DomainEvents.POLICY_UPDATED).toBe('PolicyUpdated');
    });

    it('POLICY_ENABLED equals "PolicyEnabled"', () => {
      expect(DomainEvents.POLICY_ENABLED).toBe('PolicyEnabled');
    });

    it('POLICY_DISABLED equals "PolicyDisabled"', () => {
      expect(DomainEvents.POLICY_DISABLED).toBe('PolicyDisabled');
    });

    it('POLICY_APPLIED equals "PolicyApplied"', () => {
      expect(DomainEvents.POLICY_APPLIED).toBe('PolicyApplied');
    });

    it('RULE_ADDED equals "PolicyRuleAdded"', () => {
      expect(DomainEvents.RULE_ADDED).toBe('PolicyRuleAdded');
    });

    it('RULE_REMOVED equals "PolicyRuleRemoved"', () => {
      expect(DomainEvents.RULE_REMOVED).toBe('PolicyRuleRemoved');
    });

    it('BLUEPRINT_CREATED equals "BlueprintCreated"', () => {
      expect(DomainEvents.BLUEPRINT_CREATED).toBe('BlueprintCreated');
    });

    it('BLUEPRINT_UPDATED equals "BlueprintUpdated"', () => {
      expect(DomainEvents.BLUEPRINT_UPDATED).toBe('BlueprintUpdated');
    });

    it('BLUEPRINT_DEPLOYED equals "BlueprintDeployed"', () => {
      expect(DomainEvents.BLUEPRINT_DEPLOYED).toBe('BlueprintDeployed');
    });
  });

  describe('event shape consistency', () => {
    it('all policy event names start with "Policy" or are rule events', () => {
      const policyEvents = [
        DomainEvents.POLICY_CREATED,
        DomainEvents.POLICY_UPDATED,
        DomainEvents.POLICY_ENABLED,
        DomainEvents.POLICY_DISABLED,
        DomainEvents.POLICY_DELETED,
        DomainEvents.POLICY_APPLIED,
      ];
      for (const ev of policyEvents) {
        expect(ev).toMatch(/^Policy/);
      }
    });

    it('all blueprint event names start with "Blueprint"', () => {
      const blueprintEvents = [
        DomainEvents.BLUEPRINT_CREATED,
        DomainEvents.BLUEPRINT_UPDATED,
        DomainEvents.BLUEPRINT_DEPLOYED,
        DomainEvents.BLUEPRINT_DELETED,
      ];
      for (const ev of blueprintEvents) {
        expect(ev).toMatch(/^Blueprint/);
      }
    });

    it('rule event names start with "Policy"', () => {
      expect(DomainEvents.RULE_ADDED).toMatch(/^Policy/);
      expect(DomainEvents.RULE_REMOVED).toMatch(/^Policy/);
    });
  });
});
