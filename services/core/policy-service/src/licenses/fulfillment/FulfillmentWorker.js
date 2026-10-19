'use strict';

const { uuid }=require('./contracts');
const { ProviderError }=require('./transport');
class FulfillmentWorker {
  constructor({ store,identity,graph,connectorId,tenantId,sourceClientId }) {
    Object.assign(this,{ store,identity,graph,connectorId:uuid(connectorId),tenantId:uuid(tenantId) });
    this.actor={ type:'workload',clientId:sourceClientId,connectorId }; this.running=false; this.stopped=false;
  }
  stop() { this.stopped=true; }
  async sweep() {
    if (this.running || this.stopped) return; this.running=true;
    try { for (const candidate of await this.store.candidates(this.connectorId)) { if (this.stopped) break; await this.target(candidate.id); } }
    finally { this.running=false; }
  }
  async target(id) {
    const connection=await this.store.database.getClient(); let locked=false;
    try {
      locked=(await connection.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked',[id])).rows[0].locked;
      if (!locked) return;
      let row=await this.store.row(id); if (!row?.enabled || row.business_tenant_id!=null || row.connector_id!==this.connectorId || row.tenant_id!==this.tenantId || this.graph.tenantId!==row.tenant_id) return;
      if (this.stopped || !await this.store.available(this.connectorId)) return;
      if (row.status==='in_flight') {
        await this.store.settle(row,this.actor,{ status:'unknown',error:'unfinished_write_requires_review' }); row=await this.store.row(id);
      }
      let snapshot;
      try { snapshot=await this.identity.user(row.user_id); }
      catch { await this.store.settle(row,this.actor,{ status:row.status==='unknown'?'unknown':row.status==='verifying'?'verifying':'failed',error:'identity_source_unavailable' }); return; }
      await this.store.checkpoint(row,snapshot,this.actor);
      await this.store.refresh(row); row=await this.store.row(id); if (!row?.enabled || row.business_tenant_id!=null) return;
      let observed;
      try { observed=await this.graph.inspect(row.object_id,row.sku_id,row.disabled_plans); }
      catch (error) {
        if (error instanceof ProviderError && error.code==='graph_assignment_error' && error.observation) {
          observed=error.observation;
          if (row.desired) { await this.store.settle(row,this.actor,{ status:row.status==='unknown'?'unknown':'failed',error:error.code,observation:observed }); return; }
        } else {
          if (error.retryAfter) await this.store.defer(this.connectorId,error.retryAfter);
          await this.store.settle(row,this.actor,{ status:row.status==='unknown'?'unknown':row.status==='verifying'?'verifying':'failed',error:error instanceof ProviderError?error.code:'provider_read_unavailable',delay:error.retryAfter||60 }); return;
        }
      }
      const settle=(status,error=null,owned=row.owned,delay=60)=>this.store.settle(row,this.actor,{ status,error,owned,observation:observed,delay });
      if (row.status==='unknown') {
        if (!row.desired && row.attempt_desired===false && !observed.present) await settle('confirmed',null,false);
        else await settle('unknown','uncertain_write_requires_review');
        return;
      }
      if (row.desired) {
        if (row.eligibility_revision===null || String(row.eligibility_revision)!==snapshot.revision) { await settle('conflict','entitlement_eligibility_review_required'); return; }
        if (!snapshot.enabled || snapshot.deleted || !observed.accountEnabled) { await settle('conflict','target_disabled'); return; }
        if (observed.present) {
          if (!observed.direct) await settle('conflict','external_group_or_unresolved_assignment');
          else if (!observed.plansMatch) await settle('conflict','external_plan_configuration');
          else if (!row.owned) await settle('conflict','unmanaged_direct_assignment');
          else await settle(observed.active?'confirmed':'verifying',observed.active?null:'provider_provisioning_pending');
          return;
        }
        if (row.status==='verifying' && row.attempt_desired===true) { await settle('verifying','provider_provisioning_pending'); return; }
      } else {
        if (!observed.present) { await settle('confirmed',null,false); return; }
        if (!observed.direct) { await settle('conflict','external_group_assignment_retained',false); return; }
        if (row.status==='verifying' && row.attempt_desired===false) { await settle('verifying','provider_removal_pending',false); return; }
        if (!row.owned || !observed.plansMatch) { await settle('conflict','unmanaged_assignment_retained'); return; }
      }
      if (row.status==='failed' && row.error?.startsWith('graph_write_') || row.attempt_count>=5) { await settle('failed',row.error||'attempt_limit_requires_review'); return; }
      let latest;
      try { latest=await this.identity.user(row.user_id); }
      catch { await settle('failed','identity_source_unavailable'); return; }
      await this.store.checkpoint(row,latest,this.actor); await this.store.refresh(row);
      const current=await this.store.row(id); if (!current?.enabled || current.business_tenant_id!=null || String(current.version)!==String(row.version) || row.desired && (!latest.enabled || latest.deleted || latest.revision!==String(row.eligibility_revision))) return;
      let token;
      try { token=await this.graph.tokens.get(); }
      catch { await settle('failed','graph_token_unavailable'); return; }
      if (this.stopped) return;
      let attemptId;
      try { attemptId=await this.store.writeIntent(row,this.actor); }
      catch(error) { if(error.status===409 && /^capacity_[a-z_]+$/.test(error.message)) { await settle('failed',error.message);return; }throw error; }
      if (!attemptId) return;
      const dispatchAdmitted=!this.stopped && await this.store.dispatch(row,attemptId);
      if(!dispatchAdmitted || this.stopped) {
        await this.store.settle(row,this.actor,{status:'unknown',error:this.stopped?'capacity_dispatch_stopped':'capacity_dispatch_not_admitted',attemptId,knownWrite:true,observation:observed});return;
      }
      try { await this.graph.mutate(row.object_id,row.sku_id,row.disabled_plans,row.desired,token,attemptId); }
      catch (error) {
        if (error.retryAfter) await this.store.defer(this.connectorId,error.retryAfter);
        await this.store.settle(row,this.actor,{ status:error.uncertain?'unknown':error.retryAfter?'pending':'failed',error:error instanceof ProviderError?error.code:'provider_write_uncertain',
          delay:error.retryAfter||60,observation:observed,attemptId,knownWrite:true }); return;
      }
      await this.store.settle(row,this.actor,{ status:'verifying',owned:row.desired,error:'provider_verification_pending',observation:observed,delay:1,attemptId,knownWrite:true });
    } finally {
      try { if (locked) await connection.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[id]); connection.release(); }
      catch { connection.release(true); }
    }
  }
}
module.exports = { FulfillmentWorker };
