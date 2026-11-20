'use strict';

const CompanyRoles = require('./CompanyRoleAuthority');
const C = require('../../../../packages/device-scope-contract');
function fail(status,message) { throw Object.assign(new Error(message),{status}); }
async function capture(client,user,available,tenant,inherent=[]) {
  const held = await CompanyRoles.permissions(client,user,available);
  const captured = held.length ? await CompanyRoles.capture(client,user,held) : { grants:[] };
  const grants = [];
  for(const permission of held.filter(permission=>!inherent.includes(permission))){
    const matching=captured.grants.filter(grant=>grant.permission===permission),tenantSources=matching.filter(grant=>grant.source.scopeType==='tenant');
    tenantSources.sort((a,b)=>CompanyRoles.deadline(user,{grants:[b]})-CompanyRoles.deadline(user,{grants:[a]})||a.source.id.localeCompare(b.source.id)||(a.source.activationId||'').localeCompare(b.source.activationId||''));
    grants.push(...(tenantSources.length?[tenantSources[0]]:matching.filter(grant=>grant.source.scopeType==='device-ou')));
  }
  grants.sort((a,b) => C.key(a,available).localeCompare(C.key(b,available),'en'));
  if (grants.length > C.MAX_GRANTS) fail(503,'Device scope source limit exceeded');
  const roots = [...new Map(grants.filter(grant => grant.source.scopeType === 'device-ou').map(grant => [grant.source.ouId,{id:grant.source.ouId,generation:grant.source.ouGeneration}])).values()].sort((a,b)=>a.id.localeCompare(b.id));
  if (!roots.length) return { grants,units:[] };
  const units = (await client.query(`WITH RECURSIVE tree AS (
    SELECT unit.id,namespace.generation,root.id AS root,ARRAY[unit.id] AS path FROM jsonb_to_recordset($2::jsonb) AS root(id uuid,generation bigint)
    JOIN ous unit ON unit.id=root.id JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=$1 AND namespace.generation=root.generation
    WHERE identity_tenant_id('ou',unit.id)=$1
    UNION ALL SELECT child.id,namespace.generation,tree.root,tree.path||child.id FROM ous child JOIN tree ON child.parent_id=tree.id
    JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=child.id AND namespace.tenant_id=$1
    WHERE identity_tenant_id('ou',child.id)=$1 AND cardinality(tree.path)<256 AND NOT child.id=ANY(tree.path))
    SELECT id,generation::text,array_agg(DISTINCT root::text ORDER BY root::text) AS roots FROM tree GROUP BY id,generation ORDER BY id LIMIT $3`,[tenant,JSON.stringify(roots),C.MAX_UNITS+1])).rows;
  if (units.length > C.MAX_UNITS || roots.some(root => !units.some(unit => unit.id === root.id && unit.generation === root.generation && unit.roots.includes(root.id)))) fail(503,'Current own device scope hierarchy unavailable');
  return { grants,units };
}
module.exports = { capture };
