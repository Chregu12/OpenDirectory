'use strict';

const express = require('express');
const { createHash } = require('node:crypto');
const { PolicyConfiguration, etag, fields, metadata, fail, policy, PLATFORMS } = require('./PolicyConfiguration');
const { freshPolicyAuthentication } = require('./middleware/policyAccess');
const PostgresPolicyRepository = require('./infrastructure/repositories/PostgresPolicyRepository');
const { PolicyDelivery } = require('./PolicyDelivery');
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function policyConfigurationRoutes(database, { loadTemplates, catalog, rsopEngine, conflictResolver, inheritanceEngine, compilers, store = new PolicyConfiguration(database), delivery = new PolicyDelivery() }) {
  const router = express.Router();
  const wrap = operation => async (req,res) => {
    const controller = new AbortController(); const stop = () => controller.abort(); req.once('aborted',stop);res.once('close',stop);
    req.policySignal=controller.signal;
    try { await operation(req,res); }
    catch(error) { if (!res.headersSent && !res.destroyed) res.status(error.status || 503).json({ error:error.code || 'policy_configuration_unavailable', ...(error.deliveryMayHaveOccurred ? {deliveryMayHaveOccurred:true,enforcementConfirmed:false} : {}) }); }
    finally { req.removeListener('aborted',stop);res.removeListener('close',stop); }
  };
  const auth = req => req.headers.authorization;
  const send = (res,kind,row,status=200) => res.status(status).set('ETag',etag(kind,row)).json(row);
  const observe = (req,permission,operation) => store.observe(req.user,auth(req),permission,req.policySignal,operation);
  const snapshot = (req,kind='policy',alias) => store.snapshot(kind,req.params.id,req.user,auth(req),req.policySignal,alias);
  const transition = action => wrap(async(req,res)=>{const row=await store.mutate(req.params.id,req.headers['if-match'],req.body,req.user,auth(req),action,req.policySignal);if(action==='deleted')res.status(204).set('ETag',etag('policy',row)).send();else send(res,'policy',row);});
  const child = (kind,action,childParameter,alias) => wrap(async(req,res)=>{
    const result=await store.child(kind,req.params.id,req.headers['if-match'],req.body,req.user,auth(req),action,req.policySignal,childParameter?req.params[childParameter]:undefined,alias);
    res.set('ETag',etag(kind,result.parent));if(['unlinked','configuration_removed'].includes(action))res.status(204).send();else res.status(201).json({...result.row,parentVersion:result.parent.version});
  });
  const recipe = baseline => wrap(async(req,res)=>{
    const allowed=baseline?[]:['templateId','name','description','priority'];metadata(req.body,[...allowed,'definitionHash']);
    const source=(baseline?catalog.baselines:loadTemplates()).find(row=>row.id===(baseline?req.params.id:req.body.templateId));if(!source)fail(404,'policy_recipe_not_found');
    if(req.body.definitionHash!==hash(source))fail(412,'policy_recipe_changed');
    const row=await store.create({name:req.body.name||source.name,description:req.body.description??source.description,type:baseline?'compliance':source.type,platform:source.platform||'all',settings:source.settings||{},priority:req.body.priority??50,reason:req.body.reason,acknowledgeScope:true},req.user,auth(req),req.policySignal);
    if(baseline)res.status(201).set('ETag',etag('policy',row)).json({message:'Baseline recipe saved as a draft; activation and endpoint enforcement are not confirmed',policy:row,baseline:source});else send(res,'policy',row,201);
  });
  const gpoView = (row,assignments=[]) => ({id:row.id,name:row.name,type:row.settings.gpoType,settings:row.settings.configuration,platforms:row.settings.platforms,enabled:row.status==='active',status:row.status,version:row.version,assignedTo:assignments.map(item=>item.target_id),createdAt:row.created_at,created_by:row.created_by});
  const ringView = (row,assignments=[]) => ({id:row.id,name:row.name,description:row.description,deferralDays:row.settings.deferralDays,version:row.version,status:row.status,assignedDevices:assignments.filter(item=>item.target_type==='device').map(item=>item.target_id),deviceCount:assignments.filter(item=>item.target_type==='device').length});
  const aliases = (req,type) => observe(req,'policies.read',async client=>{
    const rows=(await client.query('SELECT * FROM policies WHERE type=$1 ORDER BY created_at,id LIMIT 1001',[type])).rows;if(rows.length>1000)fail(409,'policy_catalog_limit_reached');
    const assignments=(await client.query('SELECT * FROM policy_assignments WHERE policy_id=ANY($1::uuid[]) ORDER BY id',[rows.map(row=>row.id)])).rows;
    return rows.map(row=>(type==='gpo'?gpoView:ringView)(row,assignments.filter(item=>item.policy_id===row.id)));
  });
  async function prepare(req,kind,alias) {
    fields(req.body,['acknowledgeScope','publicationId']);if(req.body.acknowledgeScope!==true)fail(400,'policy_delivery_scope_required');
    if(!req.headers['if-match'])fail(428,'policy_version_required');
    await store.check(req.user,auth(req),'policies.deploy',req.policySignal,true);const source=await snapshot(req,kind,alias);
    if(req.headers['if-match']!==etag(kind,source.row))fail(412,'policy_configuration_changed');
    if(alias==='gpo'&&source.row.status!=='active')fail(409,'active_policy_required');
    if(kind==='blueprint'){
      const preview=await store.previewBlueprints({platform:source.row.platform==='all'?'macos':source.row.platform,blueprints:[{id:source.row.id,version:source.row.version}]},req.user,auth(req),req.policySignal);
      if(preview.hasConflicts)fail(409,'blueprint_configuration_conflict');
    }
    req.policyPublicationBinding=await store.publications.assertUse(kind,source.row.id,source.row.version,req.body.publicationId,req.user,auth(req),req.policySignal);
    req.policyDeliverySource={resourceKind:kind,resourceId:source.row.id,resourceVersion:source.row.version,publicationId:req.body.publicationId};
    req.policyCommandPayloads=kind==='policy'?{gpo:{gpoId:source.row.id,gpoName:source.row.name,configurationVersion:source.row.version,settings:source.row.settings.configuration}}:Object.fromEntries(source.configurations.map(configuration=>[configuration.id,{blueprintId:source.row.id,blueprintName:source.row.name,configurationId:configuration.id,configurationVersion:source.row.version,configType:configuration.config_type,configName:configuration.config_name,settings:configuration.payload}]));
    req.policyConfigurationCheck=()=>store.publications.assertUse(kind,source.row.id,source.row.version,req.body.publicationId,req.user,auth(req),req.policySignal);return source;
  }
  router.get('/policies/access',(req,res)=>res.json({schemaVersion:4,subject:req.user.sub,userId:req.policyActor,permissions:req.policyPermissions,freshMfa:freshPolicyAuthentication(req.user),writeAuthenticationMaxAgeSeconds:300}));
  router.post('/policies/delivery/frame',wrap(async(req,res)=>res.json(await store.publications.deliveryFrame(req.body,req.user,auth(req),req.policySignal))));
  router.get('/policies/:id/publications',wrap(async(req,res)=>res.json(await store.publications.get('policy',req.params.id,req.user,auth(req),req.policySignal))));
  router.post('/policies/:id/publications',wrap(async(req,res)=>{const row=await store.publications.request('policy',req.params.id,req.headers['if-match'],req.body,req.user,auth(req),req.policySignal);res.status(201).set('ETag',require('./PolicyPublication').publicationTag(row)).json(row);}));
  router.post('/policies/:id/publications/:publicationId/decisions',wrap(async(req,res)=>{const row=await store.publications.transition('policy',req.params.id,req.params.publicationId,req.headers['if-match'],req.body,req.user,auth(req),req.policySignal);res.set('ETag',require('./PolicyPublication').publicationTag(row)).json(row);}));
  router.get('/blueprints/:id/publications',wrap(async(req,res)=>res.json(await store.publications.get('blueprint',req.params.id,req.user,auth(req),req.policySignal))));
  router.post('/blueprints/:id/publications',wrap(async(req,res)=>{const row=await store.publications.request('blueprint',req.params.id,req.headers['if-match'],req.body,req.user,auth(req),req.policySignal);res.status(201).set('ETag',require('./PolicyPublication').publicationTag(row)).json(row);}));
  router.post('/blueprints/:id/publications/:publicationId/decisions',wrap(async(req,res)=>{const row=await store.publications.transition('blueprint',req.params.id,req.params.publicationId,req.headers['if-match'],req.body,req.user,auth(req),req.policySignal);res.set('ETag',require('./PolicyPublication').publicationTag(row)).json(row);}));
  router.get('/policies',wrap(async(req,res)=>{
    fields(req.query,['page','limit','type','status','platform']);const page=Number(req.query.page??1);const limit=Number(req.query.limit??50);
    if(!Number.isInteger(page)||page<1||page>1000000||!Number.isInteger(limit)||limit<1||limit>200)fail(400,'bounded_policy_page_required');
    const filters={};for(const key of ['type','status','platform'])if(req.query[key]!==undefined){if(typeof req.query[key]!=='string'||req.query[key].length>50)fail(400,'policy_filter_required');filters[key]=req.query[key];}
    const result=await observe(req,'policies.read',client=>new PostgresPolicyRepository(client).findAll(filters,{limit,offset:(page-1)*limit}));
    res.json({policies:result.policies.map(row=>row.toJSON()),total:result.total,page,limit});
  }));
  router.get('/policies/templates',wrap(async(req,res)=>{const templates=loadTemplates().map(row=>({...row,definitionHash:hash(row)}));res.json({templates,total:templates.length});}));
  router.get('/policies/baselines',wrap(async(req,res)=>res.json({baselines:catalog.baselines.map(row=>({...row,definitionHash:hash(row)})),total:catalog.baselines.length})));
  router.get('/policies/conflicts',wrap(async(req,res)=>{const rows=await observe(req,'policies.read',async client=>(await client.query("SELECT * FROM policies WHERE status='active' ORDER BY priority,id LIMIT 1001")).rows);if(rows.length>1000)fail(409,'policy_catalog_limit_reached');const resolution=conflictResolver.resolveConflicts(rows);res.json({conflicts:resolution.conflicts,explanation:resolution.explanation,activePolicyCount:rows.length,resolvedSettingCount:Object.keys(resolution.resolved).length});}));
  router.get('/policies/simulate',wrap(async(req,res)=>{if(!req.query.deviceId&&!req.query.userId)fail(400,'policy_preview_target_required');const result=await observe(req,'policies.read',()=>rsopEngine.calculateRSOP(req.query.deviceId,req.query.userId,{}));res.json({effectiveSettings:result.settings,sources:result.sources,appliedPoliciesCount:result.appliedPolicies.length,previewOnly:true});}));
  router.get('/policies/inheritance/:ouId',wrap(async(req,res)=>res.json(await observe(req,'policies.read',()=>inheritanceEngine.getInheritanceChain('ou',req.params.ouId)))));
  router.get('/policies/inheritance/:targetType/:targetId',wrap(async(req,res)=>{if(!['ou','site','domain','device','group'].includes(req.params.targetType))fail(400,'policy_target_type_required');res.json(await observe(req,'policies.read',()=>inheritanceEngine.getInheritanceChain(req.params.targetType,req.params.targetId)));}));
  router.get('/policies/:id',wrap(async(req,res)=>send(res,'policy',(await snapshot(req)).row)));
  router.post('/policies',wrap(async(req,res)=>send(res,'policy',await store.create(req.body,req.user,auth(req),req.policySignal),201)));
  router.put('/policies/:id',transition('updated'));
  router.delete('/policies/:id',transition('deleted'));
  router.post('/policies/:id/activate',transition('activated'));
  router.post('/policies/:id/deactivate',transition('deactivated'));
  router.get('/policies/:id/assignments',wrap(async(req,res)=>{const result=await snapshot(req);res.set('ETag',etag('policy',result.row)).json({assignments:result.assignments,parentVersion:result.row.version});}));
  router.post('/policies/:id/assign',child('policy','assigned'));
  router.post('/policies/evaluate',wrap(async(req,res)=>res.json({applicablePolicies:await observe(req,'policies.deploy',async client=>(await client.query("SELECT * FROM policies WHERE status='active' ORDER BY priority,id LIMIT 1001")).rows),previewOnly:true})));
  router.post('/policies/rsop',wrap(async(req,res)=>{if(!req.body.deviceId&&!req.body.userId)fail(400,'policy_preview_target_required');res.json({rsop:await observe(req,'policies.preview',()=>rsopEngine.calculateRSOP(req.body.deviceId,req.body.userId,req.body.context||{})),previewOnly:true});}));
  router.post('/policies/from-template',recipe(false));
  router.post('/policies/baselines/:id/apply',recipe(true));
  router.post('/policies/:id/compile/:platform',wrap(async(req,res)=>{if(!Object.hasOwn(compilers,req.params.platform))fail(400,'policy_compiler_required');const source=await snapshot(req);res.set('ETag',etag('policy',source.row)).json({policyId:source.row.id,policyName:source.row.name,compiled:compilers[req.params.platform].compile({settings:rsopEngine._flattenObject(source.row.settings),sources:{},conflicts:[],appliedPolicies:[source.row]}),previewOnly:true});}));
  router.post('/policies/:id/link',child('policy','linked'));
  router.delete('/policies/:id/link/:linkId',child('policy','unlinked','linkId'));
  router.get('/policies/:id/links',wrap(async(req,res)=>{const result=await snapshot(req);res.set('ETag',etag('policy',result.row)).json({links:result.links,parentVersion:result.row.version});}));
  router.post('/policies/:id/wmi-filter',wrap(async(req,res)=>{metadata(req.body,['wmi_filter']);if(!Array.isArray(req.body.wmi_filter?.conditions)||req.body.wmi_filter.conditions.some(condition=>!condition.property||!condition.operator||condition.value===undefined))fail(400,'policy_wmi_conditions_required');send(res,'policy',await store.mutate(req.params.id,req.headers['if-match'],req.body,req.user,auth(req),'updated',req.policySignal));}));
  router.get('/policies/:id/audit',wrap(async(req,res)=>{const limit=Number(req.query.limit??50);const offset=Number(req.query.offset??0);if(!Number.isInteger(limit)||limit<1||limit>200||!Number.isInteger(offset)||offset<0||offset>1000000)fail(400,'bounded_policy_audit_page_required');const auditLog=await observe(req,'policies.audit.read',async client=>(await client.query("SELECT * FROM policy_configuration_audit WHERE resource_kind='policy' AND resource_id=$1 ORDER BY version DESC LIMIT $2 OFFSET $3",[req.params.id,limit,offset])).rows);res.json({auditLog,source:'versioned-policy-transitions',legacyEvidenceIncluded:false});}));
  router.get('/update-rings',wrap(async(req,res)=>res.json(await aliases(req,'update-ring'))));
  router.put('/update-rings/:id',wrap(async(req,res)=>{metadata(req.body,['deferralDays','description']);const before=(await snapshot(req,'policy','update-ring')).row;const body={reason:req.body.reason,acknowledgeScope:true,...(req.body.deferralDays!==undefined?{settings:{deferralDays:req.body.deferralDays}}:{}),...(req.body.description!==undefined?{description:req.body.description}:{})};const row=await store.mutate(req.params.id,req.headers['if-match'],body,req.user,auth(req),'updated',req.policySignal,'update-ring');send(res,'policy',{...ringView(row),version:row.version});}));
  router.post('/update-rings/:id/assign',wrap(async(req,res)=>{metadata(req.body,['deviceId']);const result=await store.child('policy',req.params.id,req.headers['if-match'],{targetType:'device',targetId:req.body.deviceId,reason:req.body.reason,acknowledgeScope:true},req.user,auth(req),'assigned',req.policySignal,undefined,'update-ring');res.status(201).set('ETag',etag('policy',result.parent)).json({...result.row,parentVersion:result.parent.version});}));
  router.get('/gpo',wrap(async(req,res)=>res.json(await aliases(req,'gpo'))));
  router.post('/gpo',wrap(async(req,res)=>{metadata(req.body,['type','name','settings','platforms']);const row=await store.create({name:req.body.name,type:'gpo',platform:'all',settings:{configuration:req.body.settings||{},platforms:req.body.platforms||['windows','macos','linux'],gpoType:req.body.type||'custom'},reason:req.body.reason,acknowledgeScope:true},req.user,auth(req),req.policySignal);send(res,'policy',gpoView(row),201);}));
  router.put('/gpo/:id',wrap(async(req,res)=>{metadata(req.body,['name','settings','platforms']);const before=(await snapshot(req,'policy','gpo')).row;const body={reason:req.body.reason,acknowledgeScope:true,...(req.body.name!==undefined?{name:req.body.name}:{}),settings:{...before.settings,...(req.body.settings!==undefined?{configuration:req.body.settings}:{}),...(req.body.platforms!==undefined?{platforms:req.body.platforms}:{})}};const row=await store.mutate(req.params.id,req.headers['if-match'],body,req.user,auth(req),'updated',req.policySignal,'gpo');send(res,'policy',gpoView(row));}));
  router.delete('/gpo/:id',wrap(async(req,res)=>{const row=await store.mutate(req.params.id,req.headers['if-match'],req.body,req.user,auth(req),'deleted',req.policySignal,'gpo');res.status(204).set('ETag',etag('policy',row)).send();}));
  router.get('/gpo/effective/:platform',wrap(async(req,res)=>{if(!PLATFORMS.includes(req.params.platform)||req.params.platform==='all')fail(400,'policy_platform_required');const rows=await aliases(req,'gpo');const targets=[req.query.deviceId,req.query.ouId,...(typeof req.query.groups==='string'?req.query.groups.split(','):[])].filter(Boolean);const gpos=rows.filter(row=>row.enabled&&row.platforms.includes(req.params.platform)&&row.assignedTo.some(id=>targets.includes(id)));const settings=Object.assign({},...gpos.map(row=>row.settings));res.json({platform:req.params.platform,effectivePolicies:gpos.length,settings,gpos,previewOnly:true});}));
  router.post('/gpo/:id/apply',wrap(async(req,res)=>{const source=await prepare(req,'policy','gpo');await delivery.request(req,res,'devices','/api/devices/policy-command-access');const inventory=await delivery.request(req,res,'devices','/api/devices/policy-registry');const direct=source.assignments.filter(item=>item.target_type==='device');const unsupportedTargets=source.assignments.filter(item=>item.target_type!=='device').map(item=>({targetType:item.target_type,targetId:item.target_id,reason:'canonical_device_resolution_required'}));const results=[];
    for(const target of direct){const device=inventory.body.find(item=>item.id===target.target_id);if(!device||!source.row.settings.platforms.includes(device.platform)){unsupportedTargets.push({targetType:'device',targetId:target.target_id,reason:'current_matching_device_required'});continue;}const receipt=await delivery.request(req,res,'devices',`/api/devices/${encodeURIComponent(device.id)}/commands`,{method:'POST',body:{command:'update_policy',reference:{...req.policyDeliverySource,configurationId:null}}});results.push({deviceId:device.id,commandId:receipt.body.id,queued:true,policyReceipt:receipt.body.policyReceipt});}
    res.json({gpoId:source.row.id,configurationVersion:source.row.version,devicesTargeted:results.length,results,unsupportedTargets,receiverVerified:true,phase:unsupportedTargets.length?'partial':results.length?'queued':'no-targets',enforcementConfirmed:false});
  }));
  router.get('/blueprints',wrap(async(req,res)=>{const rows=await observe(req,'policies.read',async client=>(await client.query('SELECT blueprint.*,(SELECT count(*)::int FROM blueprint_configurations WHERE blueprint_id=blueprint.id) AS config_count,(SELECT count(*)::int FROM blueprint_assignments WHERE blueprint_id=blueprint.id) AS assignment_count FROM blueprints blueprint ORDER BY created_at,id LIMIT 1001')).rows);if(rows.length>1000)fail(409,'blueprint_catalog_limit_reached');res.json({blueprints:rows,total:rows.length});}));
  router.post('/blueprints',wrap(async(req,res)=>send(res,'blueprint',await store.blueprint(req.body,req.user,auth(req),req.policySignal),201)));
  router.post('/blueprints/preview',wrap(async(req,res)=>res.set('Cache-Control','no-store').json(await store.previewBlueprints(req.body,req.user,auth(req),req.policySignal))));
  router.get('/blueprints/:id',wrap(async(req,res)=>{const result=await snapshot(req,'blueprint');send(res,'blueprint',{...result.row,configurations:result.configurations});}));
  router.put('/blueprints/:id',wrap(async(req,res)=>send(res,'blueprint',await store.blueprint(req.body,req.user,auth(req),req.policySignal,req.params.id,req.headers['if-match'],'updated'))));
  router.delete('/blueprints/:id',wrap(async(req,res)=>{const row=await store.blueprint(req.body,req.user,auth(req),req.policySignal,req.params.id,req.headers['if-match'],'deleted');res.status(204).set('ETag',etag('blueprint',row)).send();}));
  router.post('/blueprints/:id/configurations',child('blueprint','configuration_added'));
  router.delete('/blueprints/:id/configurations/:configId',child('blueprint','configuration_removed','configId'));
  router.post('/blueprints/:id/assign',child('blueprint','assigned'));
  router.get('/blueprints/:id/assignments',wrap(async(req,res)=>{const result=await snapshot(req,'blueprint');res.set('ETag',etag('blueprint',result.row)).json({assignments:result.assignments,parentVersion:result.row.version});}));
  router.post('/blueprints/:id/apply',wrap(async(req,res)=>{const source=await prepare(req,'blueprint');await delivery.request(req,res,'devices','/api/devices/policy-command-access');const results=[];const unsupportedTargets=source.assignments.filter(item=>item.target_type!=='device').map(item=>({targetType:item.target_type,targetId:item.target_id,reason:'canonical_device_resolution_required'}));
    try {for(const assignment of source.assignments.filter(item=>item.target_type==='device'))for(const configuration of source.configurations){const receipt=await delivery.request(req,res,'devices',`/api/devices/${encodeURIComponent(assignment.target_id)}/commands`,{method:'POST',body:{command:'update_policy',reference:{...req.policyDeliverySource,configurationId:configuration.id}}});results.push({targetType:'device',targetId:assignment.target_id,configType:configuration.config_type,commandId:receipt.body.id,queued:true,policyReceipt:receipt.body.policyReceipt});if(configuration.config_type==='certificate')await delivery.request(req,res,'certificates','/api/certificates/issue',{method:'POST',body:{deviceId:assignment.target_id,blueprintId:source.row.id,commonName:configuration.payload.commonName,sans:configuration.payload.sans||[]}});}}
    catch(error){return res.status(error.status||503).json({error:error.code||'policy_delivery_unconfirmed',results,deliveryMayHaveOccurred:error.deliveryMayHaveOccurred===true||results.length>0,enforcementConfirmed:false});}
    res.json({blueprintId:source.row.id,blueprintName:source.row.name,configurationVersion:source.row.version,assignmentsTargeted:source.assignments.filter(item=>item.target_type==='device').length,configuredItems:source.configurations.length,commandsQueued:results.length,results,unsupportedTargets,receiverVerified:true,phase:unsupportedTargets.length?'partial':results.length?'queued':'no-targets',enforcementConfirmed:false});
  }));
  return router;
}
module.exports={policyConfigurationRoutes};
