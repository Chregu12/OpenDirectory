'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { companyBlueprintAssignmentOpenApi } = require('../../scripts/company-blueprint-assignment-openapi');
const { organizationOpenApi } = require('../../../identity-service/scripts/organization-openapi');
const base = '/api/company-blueprint-assignments';
const apps = '/api/licenses/company/v2';
test('all new operations are uniquely merged into the published version with resolvable schema references', () => {
  const spec = organizationOpenApi(); const operations = []; const references = [];
  const visit = value => {
    if (!value || typeof value !== 'object') return;
    if (typeof value.operationId === 'string') operations.push(value.operationId);
    if (value.$ref) references.push(value.$ref);
    Object.values(value).forEach(visit);
  };
  visit(spec); expect(spec.info.version).toBe('1.20.0'); expect(new Set(operations).size).toBe(operations.length);
  expect(references.every(reference => reference.startsWith('#/components/schemas/') && Object.hasOwn(spec.components.schemas, reference.slice('#/components/schemas/'.length)))).toBe(true);
  expect(JSON.stringify(spec, null, 2) + '\n').toBe(fs.readFileSync(path.resolve(__dirname, '../../../../../docs/api/openapi.yaml'), 'utf8'));
});
test('assignment source is exactly twelve fields with independent fixed duties and explicit retained target semantics', () => {
  const source = companyBlueprintAssignmentOpenApi().components.schemas.CompanyBlueprintAssignmentSource;
  expect(source.required).toHaveLength(12); expect(source.additionalProperties).toBe(false);
  expect(source.properties.companyBlueprintAssignmentsProtocol).toEqual({ const: 1 }); expect(source.properties.companyBlueprintProtocol).toBeUndefined();
  expect(source.properties.permissions.const).toEqual(['company.blueprints.assignments.read', 'company.blueprints.assign']);
  const target = source.properties.target.anyOf.find(item => item.type === 'object'); expect(target.required).toEqual(['id', 'revision', 'eligibilityRevision', 'enabled', 'deleted']);
});
test('positive intent pins exact release, target eligibility and complete pool-version captures', () => {
  const spec = companyBlueprintAssignmentOpenApi(); const command = spec.paths[base].post;
  expect(command.parameters.map(parameter => parameter.name)).toEqual(['Idempotency-Key']);
  expect(command.requestBody.content['application/json'].schema.required).toEqual(['id', 'userId', 'blueprintId', 'version', 'eligibilityRevision', 'pools', 'reason', 'confirm']);
  expect(command.requestBody.content['application/json'].schema.properties.pools.maxItems).toBe(25);
  expect(command.description).toContain('no new effects'); expect(command.description).toContain('one effective seat');
});
test('binding removal requires both original ETag and key while read-only preview never requires a mutation key', () => {
  const spec = companyBlueprintAssignmentOpenApi();
  expect(spec.paths[base + '/{id}/remove'].post.parameters.map(parameter => parameter.name)).toEqual(['id', 'Idempotency-Key', 'If-Match']);
  expect(spec.paths[base + '/preview'].post.parameters).toEqual([]);
  expect(spec.paths[apps + '/pools/{id}/assignment-preview'].post.parameters.map(parameter => parameter.name)).toEqual(['id']);
});
test('source-aware license DTO exposes every origin instead of a single misleading direct-grant alias', () => {
  const schemas = companyBlueprintAssignmentOpenApi().components.schemas; const assignment = schemas.CompanyLicenseV2AssignmentPage.properties.assignments.items;
  expect(assignment.properties.grantId).toBeUndefined(); expect(assignment.properties.sources.items.required).toEqual(['sourceType', 'sourceId', 'grantId']);
  expect(assignment.properties.sources.items.properties.sourceType.enum).toEqual(['direct', 'blueprint']);
  const result = schemas.CompanyLicenseV2ManualReceipt.properties;
  for (const field of ['sourceAdded', 'sourceRemoved', 'seatAllocated', 'seatReleased', 'effectiveAssignmentRetained']) expect(result[field]).toEqual({ type: 'boolean' });
});
test('negative workflow includes complete source/grant and zero-app binding manifests without changing V1 schemas', () => {
  const spec = organizationOpenApi(); const next = spec.components.schemas.CompanyOffboardingV2Workflow.properties;
  expect(next.nextAssignments.maxItems).toBe(10000); expect(next.nextBindings.maxItems).toBe(10000);
  expect(next.nextAssignments.items.properties.sources.items.properties.grantId.format).toBe('uuid');
  expect(spec.components.schemas.CompanyOffboardingWorkflow.properties.nextAssignments.maxItems).toBe(25);
  const description = spec.paths[apps + '/offboarding-workflows'].post.description;
  expect(description).toContain('separate commits'); expect(description).toContain('zero-app'); expect(description).toContain('never refreshed after reactivation');
});
test('manual V2 operations require explicit idempotent original scope and never reinterpret a pool as a receipt ETag', () => {
  const spec = companyBlueprintAssignmentOpenApi(); const command = spec.paths[apps + '/pools/{id}/assignments'].post;
  expect(command.parameters.map(parameter => parameter.name)).toEqual(['id', 'Idempotency-Key', 'If-Match']);
  expect(command.responses[200].headers.ETag).toBeUndefined(); expect(command.responses[201].headers.ETag).toBeUndefined();
});
