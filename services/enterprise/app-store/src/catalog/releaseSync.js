'use strict';
const axios = require('axios');
const { randomUUID } = require('crypto');

const identifier = value => typeof value === 'string' && value.length <= 160 && /^[a-zA-Z0-9@+._-]+$/.test(value);
const safeLink = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : null; } catch { return null; } };
function sourceFor(platform, definition) {
  if (!definition || !identifier(definition.id)) return null;
  if (platform === 'macos' && definition.type === 'brew') {
    const kind = definition.cask === true ? 'cask' : 'formula';
    return { provider: 'Homebrew', id: definition.id, api: `https://formulae.brew.sh/api/${kind}/${encodeURIComponent(definition.id)}.json`, url: `https://formulae.brew.sh/${kind}/${encodeURIComponent(definition.id)}` };
  }
  if (platform === 'windows' && definition.type === 'winget' && definition.id.split('.').every(part => /^[a-zA-Z0-9_-]+$/.test(part))) {
    const path = definition.id[0].toLowerCase() + '/' + definition.id.split('.').join('/');
    return { provider: 'WinGet', id: definition.id, api: `https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/${path}`, url: `https://github.com/microsoft/winget-pkgs/tree/master/manifests/${path}` };
  }
  return null;
}
function parseRelease(source, data) {
  if (source.provider === 'Homebrew') {
    if (!data || (data.token || data.name) !== source.id) throw new Error('invalid_provider_identity');
    const version = data.version || data.versions?.stable;
    if (typeof version !== 'string' || !version || version.length > 100) throw new Error('invalid_provider_version');
    return { version, homepage: safeLink(data.homepage), deprecated: data.deprecated === true, disabled: data.disabled === true };
  }
  if (!Array.isArray(data) || data.length >= 1000) throw new Error('incomplete_provider_listing');
  const versions = data.filter(item => item?.type === 'dir' && typeof item.name === 'string' && /^\d+(?:\.\d+){1,4}$/.test(item.name)).map(item => item.name);
  if (!versions.length) throw new Error('missing_provider_version');
  versions.sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
  return { version: versions[0] };
}
class ReleaseSync {
  constructor(pool, { get = axios.get, clock = () => new Date() } = {}) { this.pool = pool; this.get = get; this.clock = clock; this.pending = null; this.status = { state: 'idle' }; }
  sync() {
    if (this.pending) return this.pending;
    this.status = { id: randomUUID(), state: 'running', startedAt: this.clock().toISOString(), completedApps: 0 };
    this.pending = this.run().then(result => {
      this.status = { ...this.status, state: 'completed', completedAt: this.clock().toISOString(), result };
      return result;
    }, error => {
      this.status = { ...this.status, state: 'failed', completedAt: this.clock().toISOString(), error: 'catalog_sync_failed' };
      throw error;
    }).finally(() => { this.pending = null; });
    return this.pending;
  }
  async run() {
    const rows = (await this.pool.query('SELECT id,name,packages,metadata FROM store_apps WHERE enabled=true ORDER BY display_name LIMIT 101')).rows;
    if (rows.length > 100) throw Object.assign(new Error('Katalogabgleich auf 100 Apps begrenzt; Bestand vor dem Abgleich eingrenzen.'), { status: 409 });
    const results = []; this.status.totalApps = rows.length;
    let index = 0;
    const refreshApp = async app => {
      const observations = {};
      for (const platform of ['windows', 'macos']) {
        const source = sourceFor(platform, app.packages?.[platform]);
        if (!source) continue;
        const saved = app.metadata?.catalogReleases?.[platform];
        const previous = saved?.packageId === source.id && saved?.provider === source.provider ? saved : {};
        const attemptedAt = this.clock().toISOString();
        try {
          const response = await this.get(source.api, { timeout: 8000, maxRedirects: 0, maxContentLength: 2 * 1024 * 1024,
            headers: { 'User-Agent': 'OpenDirectory-Catalog', Accept: 'application/json', ...(source.provider === 'WinGet' && process.env.CATALOG_GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.CATALOG_GITHUB_TOKEN}` } : {}) } });
          observations[platform] = { ...parseRelease(source, response.data), provider: source.provider, sourceUrl: source.url, packageId: source.id, status: 'confirmed', checkedAt: attemptedAt, lastAttemptAt: attemptedAt };
        } catch (error) {
          observations[platform] = { ...previous, provider: source.provider, sourceUrl: source.url, packageId: source.id, status: previous.version ? 'stale' : 'unavailable', lastAttemptAt: attemptedAt,
            error: error.response?.status === 403 || error.response?.status === 429 ? 'provider_rate_limit' : 'provider_unavailable' };
        }
      }
      if (Object.keys(observations).length) {
        // A concurrent edit of the package binding must not receive the old source's result.
        const saved = await this.pool.query("UPDATE store_apps SET metadata=jsonb_set(COALESCE(metadata,'{}'::jsonb),'{catalogReleases}',COALESCE(metadata->'catalogReleases','{}'::jsonb) || $2::jsonb), updated_at=NOW() WHERE id=$1 AND packages=$3::jsonb RETURNING id", [app.id, JSON.stringify(observations), JSON.stringify(app.packages)]);
        if (saved.rowCount !== 1) throw new Error('catalog_binding_changed');
      }
      results.push({ appId: app.id, name: app.name, platforms: Object.fromEntries(Object.entries(observations).map(([platform, value]) => [platform, { status: value.status, version: value.version || null }])) });
      this.status.completedApps = results.length;
    };
    await Promise.all(Array.from({ length: Math.min(3, rows.length) }, async () => { while (index < rows.length) { const app = rows[index++]; await refreshApp(app); } }));
    const total = results.reduce((sum, row) => sum + Object.keys(row.platforms).length, 0);
    const confirmed = results.reduce((sum, row) => sum + Object.values(row.platforms).filter(value => value.status === 'confirmed').length, 0);
    return { checkedAt: this.clock().toISOString(), totalSources: total, confirmedSources: confirmed, partial: confirmed !== total, apps: results };
  }
}
module.exports = { ReleaseSync, sourceFor, parseRelease, safeLink };
