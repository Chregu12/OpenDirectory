'use strict';

const {ProviderStore}=require('./ProviderStore');
const {uuid,fail}=require('./contracts');
class CapacityReports {
  constructor(allocator,options={}){this.allocator=allocator;this.provider=new ProviderStore(allocator,options);}
  async get(connectorId,user,principal,authorization){
    uuid(connectorId);this.provider.actor(user,principal,'licenses.fulfillment.read');
    return this.allocator.transaction(async client=>{
      await this.provider.revalidate(user,authorization);this.provider.actor(user,principal,'licenses.fulfillment.read');
      const source=(await client.query('SELECT * FROM license_capacity_sources WHERE connector_id=$1 AND enabled FOR SHARE',[connectorId])).rows[0];
      const connector=(await client.query('SELECT * FROM license_provider_connectors WHERE id=$1 FOR SHARE',[connectorId])).rows[0];if(!connector)fail(404,'provider_binding_not_found');
      const run=(await client.query(`SELECT run.*,license_capacity_now() AS now FROM license_capacity_runs run JOIN license_capacity_sources source ON source.id=run.source_id
        WHERE source.connector_id=$1 ORDER BY run.run_number DESC LIMIT 1`,[connectorId])).rows[0];
      let current=!!(connector.enabled&&source&&run?.status==='complete'&&run.source_id===source.id&&String(run.source_version)===String(source.version)&&String(run.connector_version)===String(connector.version)
        &&new Date(run.started_at).getTime()<=new Date(run.now).getTime()+5000&&new Date(run.valid_until)>new Date(run.now));
      const rows=(await client.query(`SELECT product.*,catalog.name,catalog.total_seats,to_jsonb(budget) AS budget,
        (SELECT count(*)::int FROM license_capacity_reservations WHERE budget_id=budget.id) AS charged_units,(SELECT count(*)::int FROM license_assignments assignment
        WHERE assignment.license_id=product.license_id AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now())) AS unexpired_assignments
        FROM license_provider_products product JOIN license_catalog catalog ON catalog.id=product.license_id LEFT JOIN LATERAL
        (SELECT * FROM license_capacity_budgets WHERE product_id=product.id ORDER BY generation DESC LIMIT 1) budget ON true
        WHERE product.connector_id=$1 AND catalog.business_tenant_id IS NULL ORDER BY product.id LIMIT 1001`,[connectorId])).rows;
      if(rows.length>1000)fail(409,'bounded_capacity_product_inventory_required');
      await this.provider.revalidate(user,authorization);this.provider.actor(user,principal,'licenses.fulfillment.read');if(run&&new Date(run.valid_until).getTime()<=Date.now())current=false;
      const products=rows.map(row=>{
        const vendor=run?.status==='complete'?run.payload.find(item=>item.skuId===row.sku_id)||null:null;const issues=[];
        if(!current)issues.push('observation-unavailable');if(!row.enabled)issues.push('product-paused');if(!vendor)issues.push('sku-not-observed');
        if(vendor?.appliesTo!=='User'&&vendor)issues.push('company-sku');if(vendor&&vendor.capabilityStatus!=='Enabled')issues.push('vendor-status-not-enabled');
        if(row.total_seats===0)issues.push('local-unlimited');if(vendor&&row.total_seats>vendor.prepaidUnits.enabled)issues.push('local-capacity-exceeds-enabled');
        if(vendor&&row.unexpired_assignments>vendor.prepaidUnits.enabled)issues.push('local-assignments-exceed-enabled');
        return{productId:row.id,licenseId:row.license_id,skuId:row.sku_id,version:String(row.version),enabled:row.enabled,name:row.name,
          local:{configuredSeats:row.total_seats,unlimited:row.total_seats===0,unexpiredAssignments:row.unexpired_assignments},vendor,
          admission:row.budget?{budgetId:row.budget.id,reviewedUnits:row.budget.units,chargedUnits:row.charged_units,remainingUnits:Math.max(0,row.budget.units-row.charged_units),
            generationCurrent:!!(connector.enabled&&row.enabled&&source&&source.id===row.budget.source_id&&String(source.version)===String(row.budget.source_version)&&String(connector.version)===String(row.budget.connector_version)&&String(row.version)===String(row.budget.product_version))}:null,
          conservativeHeadroom:current&&row.enabled&&vendor?.appliesTo==='User'&&vendor.capabilityStatus==='Enabled'?Math.max(0,vendor.prepaidUnits.enabled-vendor.consumedUnits):null,issues};
      });
      return{schemaVersion:2,connectorId,tenantId:connector.tenant_id,connectorVersion:String(connector.version),enabled:connector.enabled,
        source:source?{id:source.id,graphClientId:source.graph_client_id,version:String(source.version)}:null,
        observation:run?{id:run.id,status:run.status,startedAt:new Date(run.started_at).toISOString(),finishedAt:run.finished_at?new Date(run.finished_at).toISOString():null,
          validUntil:new Date(run.valid_until).toISOString(),payloadHash:run.payload_hash,current,error:run.error}:null,
        products,readOnly:true,allocationChanged:false,providerFulfillmentConfirmed:false};
    });
  }
}
module.exports={CapacityReports};
