import { api } from './api';

const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const platforms = ['windows', 'macos', 'linux'];
export type BlueprintPreviewPlatform = 'windows' | 'macos' | 'linux';
export interface BlueprintPreviewRequest { platform: BlueprintPreviewPlatform; blueprints: { id: string; version: number }[] }
export interface BlueprintPreviewSource { blueprintId: string; configurationId: string }
export interface BlueprintPreviewVariant { payloadJson: string; sources: BlueprintPreviewSource[] }
export interface BlueprintPreviewResult {
  schemaVersion: 1; scope: 'selected-blueprint-versions'; comparison: 'whole-config-type'; platform: BlueprintPreviewPlatform;
  previewOnly: true; enforcementConfirmed: false; licenseReservations: 0;
  blueprints: { id: string; name: string; platform: BlueprintPreviewPlatform | 'all'; version: number }[];
  configurationCount: number; hasConflicts: boolean;
  effectiveConfigurations: (BlueprintPreviewVariant & { configType: string })[];
  conflicts: { configType: string; variants: BlueprintPreviewVariant[] }[];
}
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value: unknown, keys: string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}
function fail(): never { throw new Error('Blueprint-Vorschau nicht bestätigt. Auswahl und Berechtigungen ausdrücklich neu prüfen.'); }
function identifier(value: unknown): value is string { return typeof value === 'string' && uuid.test(value); }
function version(value: unknown): value is number { return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 2147483647; }
function capture(input: BlueprintPreviewRequest): BlueprintPreviewRequest {
  if (!exact(input, ['platform', 'blueprints']) || !platforms.includes(input.platform as string) || !Array.isArray(input.blueprints)
    || input.blueprints.length < 1 || input.blueprints.length > 25) return fail();
  const identifiers = new Set<string>();
  const blueprints = input.blueprints.map(item => {
    if (!exact(item, ['id', 'version']) || !identifier(item.id) || !version(item.version) || identifiers.has(item.id)) return fail();
    identifiers.add(item.id); return { id: item.id, version: item.version };
  });
  return { platform: input.platform as BlueprintPreviewPlatform, blueprints };
}
function parse(value: unknown, requested: BlueprintPreviewRequest): BlueprintPreviewResult {
  if (!exact(value, ['schemaVersion', 'scope', 'comparison', 'platform', 'previewOnly', 'enforcementConfirmed', 'licenseReservations', 'blueprints', 'configurationCount', 'hasConflicts', 'effectiveConfigurations', 'conflicts'])
    || value.schemaVersion !== 1 || value.scope !== 'selected-blueprint-versions' || value.comparison !== 'whole-config-type' || value.platform !== requested.platform
    || value.previewOnly !== true || value.enforcementConfirmed !== false || value.licenseReservations !== 0
    || !Array.isArray(value.blueprints) || value.blueprints.length !== requested.blueprints.length
    || typeof value.configurationCount !== 'number' || !Number.isInteger(value.configurationCount) || value.configurationCount < 0 || value.configurationCount > 1000
    || !Array.isArray(value.effectiveConfigurations) || value.effectiveConfigurations.length > 1000 || !Array.isArray(value.conflicts) || value.conflicts.length > 500
    || typeof value.hasConflicts !== 'boolean' || value.hasConflicts !== (value.conflicts.length > 0)) return fail();
  const selected = new Map(requested.blueprints.map(item => [item.id, item.version])); const blueprintIds = new Set<string>();
  for (const blueprint of value.blueprints) {
    if (!exact(blueprint, ['id', 'name', 'platform', 'version']) || !identifier(blueprint.id) || !version(blueprint.version)
      || selected.get(blueprint.id) !== blueprint.version || blueprintIds.has(blueprint.id) || typeof blueprint.name !== 'string' || !blueprint.name
      || blueprint.platform !== 'all' && blueprint.platform !== requested.platform) return fail();
    blueprintIds.add(blueprint.id);
  }
  const configurationIds = new Set<string>(); const configTypes = new Set<string>(); let payloadBytes = 0;
  const variant = (item: Record<string, unknown>) => {
    if (typeof item.payloadJson !== 'string' || !Array.isArray(item.sources) || !item.sources.length || item.sources.length > 1000) return fail();
    payloadBytes += new Blob([item.payloadJson]).size;
    if (payloadBytes > 1048576) return fail();
    try { if (!record(JSON.parse(item.payloadJson))) return fail(); } catch { return fail(); }
    for (const source of item.sources) {
      if (!exact(source, ['blueprintId', 'configurationId']) || !identifier(source.blueprintId) || !blueprintIds.has(source.blueprintId)
        || !identifier(source.configurationId) || configurationIds.has(source.configurationId)) return fail();
      configurationIds.add(source.configurationId); if (configurationIds.size > 1000) return fail();
    }
  };
  const configType = (type: unknown) => {
    if (typeof type !== 'string' || !type.length || type.length > 100 || configTypes.has(type)) return fail();
    configTypes.add(type);
  };
  for (const item of value.effectiveConfigurations) {
    if (!exact(item, ['configType', 'payloadJson', 'sources'])) return fail();
    configType(item.configType); variant(item);
  }
  for (const conflict of value.conflicts) {
    if (!exact(conflict, ['configType', 'variants']) || !Array.isArray(conflict.variants) || conflict.variants.length < 2 || conflict.variants.length > 1000) return fail();
    configType(conflict.configType); const payloads = new Set<string>();
    for (const item of conflict.variants) {
      if (!exact(item, ['payloadJson', 'sources']) || typeof item.payloadJson !== 'string' || payloads.has(item.payloadJson)) return fail();
      payloads.add(item.payloadJson); variant(item);
    }
  }
  if (configurationIds.size !== value.configurationCount) return fail();
  return value as unknown as BlueprintPreviewResult;
}
export const blueprintPreview = {
  async compare(input: BlueprintPreviewRequest, signal?: AbortSignal): Promise<BlueprintPreviewResult> {
    const requested = capture(input); const response = await api.post('/api/blueprints/preview', requested, { signal });
    if (response.status !== 200) return fail();
    return parse(response.data, requested);
  },
};
export function blueprintPreviewError(failure: unknown): string {
  const status = (failure as { response?: { status?: number } })?.response?.status;
  if (status === 412) return 'Ausgewählte Blueprint-Version nicht mehr aktuell. Katalog ausdrücklich neu laden und Versionen neu auswählen; keine automatische Aktualisierung.';
  if (status === 404) return 'Ein ausgewählter Blueprint ist nicht mehr verfügbar. Katalog ausdrücklich neu laden und neu auswählen.';
  if (status === 409) return 'Auswahl, Plattform oder Vorschaugrenze nicht bestätigt. Auswahl prüfen; keine automatische Wiederholung.';
  if (status === 401 || status === 403) return 'Sitzung oder Blueprint-Lese- und Vorschauberechtigung nicht bestätigt. Berechtigungen ausdrücklich neu laden.';
  return 'Blueprint-Vorschau nicht bestätigt. Auswahl und Berechtigungen ausdrücklich neu prüfen; keine automatische Wiederholung.';
}
