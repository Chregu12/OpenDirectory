'use strict';

const { blueprintPreviewOpenApi } = require('../../scripts/blueprint-preview-openapi');
test('preview API documents exact selected versions, precision-preserving payload text and no invented effects', () => {
  const document = blueprintPreviewOpenApi(); const schemas = document.components.schemas;
  const operation = document.paths['/api/blueprints/preview'].post;
  expect(operation.operationId).toBe('previewSelectedBlueprintVersions');
  expect(schemas.BlueprintPreviewRequest.additionalProperties).toBe(false);
  expect(schemas.BlueprintPreviewRequest.required).toEqual(['platform', 'blueprints']);
  expect(schemas.BlueprintPreviewRequest.properties.blueprints.maxItems).toBe(25);
  expect(schemas.BlueprintPreviewRequest.properties.blueprints.items.properties.version.maximum).toBe(2147483647);
  expect(schemas.BlueprintPreviewResult.properties.previewOnly.const).toBe(true);
  expect(schemas.BlueprintPreviewResult.properties.enforcementConfirmed.const).toBe(false);
  expect(schemas.BlueprintPreviewResult.properties.licenseReservations.const).toBe(0);
  expect(schemas.BlueprintPreviewResult.properties.effectiveConfigurations.items.properties.payloadJson.type).toBe('string');
  expect(schemas.BlueprintPreviewResult.properties.effectiveConfigurations.items.properties.payload).toBeUndefined();
  expect(schemas.BlueprintPreviewResult.properties.conflicts.items.properties.variants.minItems).toBe(2);
  expect(operation.responses[412]).toBeDefined(); expect(operation.responses[409]).toBeDefined();
  expect(operation.responses[200].headers['Cache-Control'].schema.const).toBe('no-store');
});
