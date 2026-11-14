BEGIN;
ALTER TABLE device_agent_connections ADD COLUMN IF NOT EXISTS security_report JSONB;
ALTER TABLE device_agent_connections ADD COLUMN IF NOT EXISTS compliance_report JSONB;
CREATE TABLE IF NOT EXISTS device_compliance_policies (
 tenant_id UUID NOT NULL, platform TEXT NOT NULL CHECK(platform IN('macos','windows','linux')), revision BIGINT NOT NULL CHECK(revision>0),
 settings JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, PRIMARY KEY(tenant_id,platform)
);
CREATE TABLE IF NOT EXISTS device_compliance_policy_events (
 id UUID PRIMARY KEY, tenant_id UUID NOT NULL, platform TEXT NOT NULL, actor_user_id UUID NOT NULL, reason TEXT NOT NULL,
 correlation_id UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL, before_state JSONB, after_state JSONB NOT NULL, source JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS device_compliance_policy_history ON device_compliance_policy_events(tenant_id,platform,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS device_compliance_policy_outbox (
 id UUID PRIMARY KEY REFERENCES device_compliance_policy_events(id), tenant_id UUID NOT NULL, status TEXT NOT NULL CHECK(status='pending')
);
CREATE TABLE IF NOT EXISTS device_compliance_events (
 id UUID PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), tenant_id UUID NOT NULL, correlation_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL, before_state JSONB, after_state JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS device_compliance_history ON device_compliance_events(tenant_id,device_id,created_at DESC,id DESC);
CREATE OR REPLACE FUNCTION device_security_valid(facts JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE part JSONB; field TEXT;
BEGIN
 IF facts IS NULL OR jsonb_typeof(facts) IS DISTINCT FROM 'object' OR NOT facts ?& ARRAY['schemaVersion','osVersion','diskEncryption','firewall'] OR facts-ARRAY['schemaVersion','osVersion','diskEncryption','firewall']<>'{}'::jsonb OR facts->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN RETURN false;END IF;
 IF facts->'osVersion'<>'null'::jsonb AND (jsonb_typeof(facts->'osVersion') IS DISTINCT FROM 'string' OR facts->>'osVersion' !~ '^[0-9]{1,6}(\.[0-9]{1,6}){0,3}$' OR facts->>'osVersion' ~ '[[:space:]]') THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['diskEncryption','firewall'] LOOP
  part=facts->field;
  IF jsonb_typeof(part) IS DISTINCT FROM 'object' OR NOT part ?& ARRAY['state','reason'] OR part-ARRAY['state','reason']<>'{}'::jsonb THEN RETURN false;END IF;
  IF part->>'state' IN('enabled','disabled') THEN IF part->>'reason' IS DISTINCT FROM 'checked' THEN RETURN false;END IF;
  ELSIF part->>'state'='unknown' THEN IF NOT coalesce(part->>'reason' IN('probe-failed','timeout','unrecognized','not-supported'),false) THEN RETURN false;END IF;
  ELSE RETURN false;END IF;
 END LOOP;
 RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_policy_valid(settings JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF settings IS NULL OR jsonb_typeof(settings) IS DISTINCT FROM 'object' OR NOT settings ?& ARRAY['enabled','maxReportAgeSeconds','minimumOsVersion','requireDiskEncryption','requireFirewall','minimumDiskFreePercent'] OR settings-ARRAY['enabled','maxReportAgeSeconds','minimumOsVersion','requireDiskEncryption','requireFirewall','minimumDiskFreePercent']<>'{}'::jsonb THEN RETURN false;END IF;
 IF jsonb_typeof(settings->'enabled') IS DISTINCT FROM 'boolean' OR jsonb_typeof(settings->'requireDiskEncryption') IS DISTINCT FROM 'boolean' OR jsonb_typeof(settings->'requireFirewall') IS DISTINCT FROM 'boolean' OR jsonb_typeof(settings->'maxReportAgeSeconds') IS DISTINCT FROM 'number' THEN RETURN false;END IF;
 IF (settings->>'maxReportAgeSeconds')::numeric NOT BETWEEN 300 AND 86400 OR mod((settings->>'maxReportAgeSeconds')::numeric,60)<>0 OR trunc((settings->>'maxReportAgeSeconds')::numeric)<>(settings->>'maxReportAgeSeconds')::numeric THEN RETURN false;END IF;
 IF settings->'minimumOsVersion'<>'null'::jsonb AND (jsonb_typeof(settings->'minimumOsVersion') IS DISTINCT FROM 'string' OR settings->>'minimumOsVersion' !~ '^[0-9]{1,6}(\.[0-9]{1,6}){0,3}$' OR settings->>'minimumOsVersion' ~ '[[:space:]]') THEN RETURN false;END IF;
 IF settings->'minimumDiskFreePercent'<>'null'::jsonb THEN
  IF jsonb_typeof(settings->'minimumDiskFreePercent') IS DISTINCT FROM 'number' THEN RETURN false;END IF;
  IF (settings->>'minimumDiskFreePercent')::numeric NOT BETWEEN 0 AND 99 OR trunc((settings->>'minimumDiskFreePercent')::numeric)<>(settings->>'minimumDiskFreePercent')::numeric THEN RETURN false;END IF;
 END IF;
 IF (settings->>'enabled')::boolean AND NOT (settings->>'requireDiskEncryption')::boolean AND NOT (settings->>'requireFirewall')::boolean AND settings->'minimumOsVersion'='null'::jsonb AND settings->'minimumDiskFreePercent'='null'::jsonb THEN RETURN false;END IF;
 RETURN true;
END; $$;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_agent_connections'::regclass AND conname='device_security_shape') THEN
  ALTER TABLE device_agent_connections ADD CONSTRAINT device_security_shape CHECK(security_report IS NULL OR (
   jsonb_typeof(security_report)='object' AND security_report ?& ARRAY['schemaVersion','facts','receivedAt','enrolledAt','revision','platform','agentVersion'] AND security_report-ARRAY['schemaVersion','facts','receivedAt','enrolledAt','revision','platform','agentVersion']='{}'::jsonb AND security_report->'schemaVersion'='1'::jsonb AND device_security_valid(security_report->'facts')));
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_compliance_policies'::regclass AND conname='device_compliance_policy_shape') THEN ALTER TABLE device_compliance_policies ADD CONSTRAINT device_compliance_policy_shape CHECK(device_compliance_policy_valid(settings));END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_policy_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; expected JSONB;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Compliance policy history is retained' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.device_compliance_policy',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Original policy command required' USING ERRCODE='42501';END IF;
 expected=CASE TG_TABLE_NAME WHEN 'device_compliance_policies' THEN proof->'after' WHEN 'device_compliance_policy_events' THEN proof->'event' ELSE proof->'outbox' END;
 IF to_jsonb(NEW) IS DISTINCT FROM expected OR (TG_OP='UPDATE' AND (TG_TABLE_NAME<>'device_compliance_policies' OR to_jsonb(OLD) IS DISTINCT FROM proof->'before')) THEN RAISE EXCEPTION 'Exact compliance policy effect required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_event_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Device compliance history is retained' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR to_jsonb(NEW) IS DISTINCT FROM proof->'complianceEvent' THEN RAISE EXCEPTION 'Exact original device assessment required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM device_agent_inventory_receiving();
 FOREACH relation IN ARRAY ARRAY['device_compliance_policies','device_compliance_policy_events','device_compliance_policy_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_compliance_policy_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_compliance_policy_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_compliance_policy_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_compliance_policy_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_compliance_policy_commit' AND tgtype=21 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_compliance_policy_commit()'::regprocedure) THEN RAISE EXCEPTION 'Compliance policy receivers unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_compliance_events'::regclass AND tgname='device_compliance_event_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_compliance_event_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_compliance_events'::regclass AND tgname='device_compliance_event_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_compliance_event_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_compliance_policies'::regclass AND conname='device_compliance_policy_shape' AND convalidated)
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_agent_connections'::regclass AND conname='device_security_shape' AND convalidated) THEN RAISE EXCEPTION 'Device assessment receivers unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_policy_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual JSONB;
BEGIN
 PERFORM device_compliance_receiving();proof=NULLIF(current_setting('opendirectory.device_compliance_policy',true),'')::jsonb;
 SELECT to_jsonb(policy) INTO actual FROM device_compliance_policies policy WHERE tenant_id=(proof#>>'{after,tenant_id}')::uuid AND platform=proof#>>'{after,platform}';
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR actual IS DISTINCT FROM proof->'after'
  OR NOT EXISTS(SELECT 1 FROM device_compliance_policy_events event WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(event)=proof->'event')
  OR NOT EXISTS(SELECT 1 FROM device_compliance_policy_outbox outbox WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(outbox)=proof->'outbox') THEN RAISE EXCEPTION 'Actual policy, history and pending receipt required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_policy_change(command JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_compliance_policies; next_state device_compliance_policies; event device_compliance_policy_events; outbox device_compliance_policy_outbox; source JSONB; deadline NUMERIC; moment TIMESTAMPTZ;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','') OR NULLIF(current_setting('opendirectory.device_compliance_policy',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Original database owner policy command required' USING ERRCODE='42501';END IF;
 PERFORM device_compliance_receiving();source=command->'source';deadline=(source->>'validUntil')::numeric;moment=clock_timestamp();
 IF source->>'schemaVersion' IS DISTINCT FROM '1' OR NOT coalesce(source->'permissions' ? 'devices.compliance.manage',false) OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
  OR deadline IS NULL OR deadline<=extract(epoch FROM moment) OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::numeric OR source->'target'<>'null'::jsonb
  OR command->>'platform' NOT IN('macos','windows','linux') OR NOT device_compliance_policy_valid(command->'settings') OR length(command->>'reason') NOT BETWEEN 10 AND 500 THEN RAISE EXCEPTION 'Original compliance manager proof required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('device-compliance:'||(source#>>'{tenant,id}')||':'||(command->>'platform'),0));
 SELECT * INTO previous FROM device_compliance_policies WHERE tenant_id=(source#>>'{tenant,id}')::uuid AND platform=command->>'platform' FOR UPDATE;
 IF command->>'expectedRevision' IS DISTINCT FROM coalesce(previous.revision,0)::text THEN RAISE EXCEPTION 'Current policy revision required' USING ERRCODE='23514';END IF;
 IF previous.settings IS NOT DISTINCT FROM command->'settings' THEN RAISE EXCEPTION 'Policy unchanged' USING ERRCODE='23514';END IF;
 next_state.tenant_id=(source#>>'{tenant,id}')::uuid;next_state.platform=command->>'platform';next_state.revision=coalesce(previous.revision,0)+1;next_state.settings=command->'settings';next_state.created_at=coalesce(previous.created_at,moment);next_state.updated_at=moment;
 event.id=(command->>'eventId')::uuid;event.tenant_id=next_state.tenant_id;event.platform=next_state.platform;event.actor_user_id=(source->>'actorUserId')::uuid;event.reason=command->>'reason';event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;event.before_state=CASE WHEN previous.tenant_id IS NULL THEN NULL ELSE to_jsonb(previous) END;event.after_state=to_jsonb(next_state);event.source=source;
 outbox.id=event.id;outbox.tenant_id=event.tenant_id;outbox.status='pending';
 PERFORM set_config('opendirectory.device_compliance_policy',jsonb_build_object('transactionId',txid_current()::text,'validUntil',deadline,'before',event.before_state,'after',to_jsonb(next_state),'event',to_jsonb(event),'outbox',to_jsonb(outbox))::text,true);
 IF previous.tenant_id IS NULL THEN INSERT INTO device_compliance_policies SELECT next_state.*;ELSE UPDATE device_compliance_policies SET revision=next_state.revision,settings=next_state.settings,updated_at=next_state.updated_at WHERE tenant_id=next_state.tenant_id AND platform=next_state.platform;END IF;
 INSERT INTO device_compliance_policy_events SELECT event.*;INSERT INTO device_compliance_policy_outbox SELECT outbox.*;
END; $$;
CREATE OR REPLACE FUNCTION device_compliance_evaluate(state device_agent_connections,moment TIMESTAMPTZ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE policy device_compliance_policies; settings JSONB; facts JSONB=state.security_report->'facts'; checks JSONB='[]'; entry JSONB; actual JSONB; expected JSONB; result TEXT; reason TEXT; field TEXT; versions INT[]; minimum INT[]; hardware JSONB; deadline TIMESTAMPTZ; assessment JSONB; fingerprint JSONB;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('device-compliance:'||state.tenant_id::text||':'||state.platform,0));
 SELECT * INTO policy FROM device_compliance_policies WHERE tenant_id=state.tenant_id AND platform=state.platform FOR SHARE;
 settings=coalesce(policy.settings,'{"enabled":false,"maxReportAgeSeconds":3600,"minimumOsVersion":null,"requireDiskEncryption":false,"requireFirewall":false,"minimumDiskFreePercent":null}'::jsonb);
 deadline=least(state.credential_expires_at,moment+make_interval(secs=>(settings->>'maxReportAgeSeconds')::int));
 IF (settings->>'enabled')::boolean THEN
  IF settings->'minimumOsVersion'<>'null'::jsonb THEN
   actual=facts->'osVersion';expected=settings->'minimumOsVersion';result='unknown';reason='not-reported';
   IF actual<>'null'::jsonb THEN
    SELECT array_agg(coalesce((string_to_array(facts->>'osVersion','.'))[n]::int,0) ORDER BY n),array_agg(coalesce((string_to_array(settings->>'minimumOsVersion','.'))[n]::int,0) ORDER BY n) INTO versions,minimum FROM generate_series(1,4) n;
    result=CASE WHEN versions>=minimum THEN 'pass' ELSE 'fail' END;reason='checked';
   END IF;
   checks=checks||jsonb_build_array(jsonb_build_object('id','os-version','status',result,'actual',actual,'expected',expected,'reason',reason));
  END IF;
  FOREACH field IN ARRAY ARRAY['diskEncryption','firewall'] LOOP
   IF (settings->>CASE field WHEN 'diskEncryption' THEN 'requireDiskEncryption' ELSE 'requireFirewall' END)::boolean THEN
    actual=facts#>ARRAY[field,'state'];result=CASE actual#>>'{}' WHEN 'enabled' THEN 'pass' WHEN 'disabled' THEN 'fail' ELSE 'unknown' END;
    checks=checks||jsonb_build_array(jsonb_build_object('id',CASE field WHEN 'diskEncryption' THEN 'disk-encryption' ELSE 'firewall' END,'status',result,'actual',actual,'expected',true,'reason',facts#>>ARRAY[field,'reason']));
   END IF;
  END LOOP;
  IF settings->'minimumDiskFreePercent'<>'null'::jsonb THEN
   result='unknown';reason='source-not-current';actual=NULL;
   IF state.inventory_report IS NOT NULL AND (state.inventory_report->>'enrolledAt')::timestamptz=state.enrolled_at AND (state.inventory_report->>'receivedAt')::timestamptz<=moment AND (state.inventory_report->>'receivedAt')::timestamptz+make_interval(secs=>(settings->>'maxReportAgeSeconds')::int)>moment THEN
    actual=state.inventory_report#>'{facts,systemDisk}';reason='not-reported';
    IF actual<>'null'::jsonb THEN
     result=CASE WHEN (actual->>'availableBytes')::numeric*100>=(actual->>'totalBytes')::numeric*(settings->>'minimumDiskFreePercent')::numeric THEN 'pass' ELSE 'fail' END;reason='checked';
     hardware=jsonb_build_object('receivedAt',state.inventory_report->'receivedAt','enrolledAt',state.inventory_report->'enrolledAt','revision',state.inventory_report->'revision','systemDisk',actual);
     deadline=least(deadline,(state.inventory_report->>'receivedAt')::timestamptz+make_interval(secs=>(settings->>'maxReportAgeSeconds')::int));
    END IF;
   END IF;
   checks=checks||jsonb_build_array(jsonb_build_object('id','disk-free','status',result,'actual',actual,'expected',settings->'minimumDiskFreePercent','reason',reason));
  END IF;
 END IF;
 result=CASE WHEN NOT (settings->>'enabled')::boolean THEN 'not-configured' WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(checks) item WHERE item->>'status'='fail') THEN 'non-compliant' WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(checks) item WHERE item->>'status'='unknown') THEN 'unknown' ELSE 'compliant' END;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',item->'id','status',item->'status','reason',item->'reason')),'[]'::jsonb) INTO fingerprint FROM jsonb_array_elements(checks) item;
 RETURN jsonb_build_object('schemaVersion',1,'tenantId',state.tenant_id,'deviceId',state.device_id,'platform',state.platform,'policyRevision',coalesce(policy.revision,0)::text,'policySettings',settings,'evaluatedAt',moment,'validUntil',deadline,'enrolledAt',state.enrolled_at,'agentRevision',state.revision::text,'security',state.security_report,'hardware',hardware,'checks',checks,'status',result,
  'fingerprint',md5(jsonb_build_object('policy',coalesce(policy.revision,0)::text,'enrollment',state.enrolled_at,'facts',facts,'checks',fingerprint)::text));
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['device_compliance_policies','device_compliance_policy_events','device_compliance_policy_outbox'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER device_compliance_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION device_compliance_policy_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER device_compliance_policy_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION device_compliance_policy_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS device_compliance_policy_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER device_compliance_policy_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION device_compliance_policy_commit()',relation);
 END LOOP;
END; $$;
CREATE OR REPLACE TRIGGER device_compliance_event_guard BEFORE INSERT OR UPDATE OR DELETE ON device_compliance_events FOR EACH ROW EXECUTE FUNCTION device_compliance_event_guard();
CREATE OR REPLACE TRIGGER device_compliance_event_truncate BEFORE TRUNCATE ON device_compliance_events FOR EACH STATEMENT EXECUTE FUNCTION device_compliance_event_guard();
CREATE OR REPLACE FUNCTION device_compliance_current(tenant UUID,platform_name TEXT,state device_agent_connections,moment TIMESTAMPTZ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE policy device_compliance_policies; status TEXT; report JSONB=state.compliance_report;
BEGIN
 SELECT * INTO policy FROM device_compliance_policies WHERE tenant_id=tenant AND platform=platform_name;
 IF policy.tenant_id IS NULL OR NOT (policy.settings->>'enabled')::boolean THEN status='not-configured';
 ELSIF report IS NULL THEN status='pending';
 ELSIF state.revoked_at IS NOT NULL OR state.credential_hash IS NULL OR state.credential_expires_at<=moment OR (report->>'enrolledAt')::timestamptz IS DISTINCT FROM state.enrolled_at OR state.platform IS DISTINCT FROM platform_name THEN status='historical';
 ELSIF report->>'policyRevision' IS DISTINCT FROM policy.revision::text THEN status='pending';
 ELSIF (report->>'validUntil')::timestamptz<=moment THEN status='stale';
 ELSE status=report->>'status';END IF;
 RETURN jsonb_build_object('status',status,'policyRevision',coalesce(policy.revision,0)::text,'assessment',report);
END; $$;
CREATE OR REPLACE FUNCTION device_agent_change(command JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_agent_connections; next_state device_agent_connections; unit devices;
 source JSONB; event device_agent_events; envelope JSONB; moment TIMESTAMPTZ; deadline DOUBLE PRECISION; action TEXT; compliance_event device_compliance_events;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  OR NULLIF(current_setting('opendirectory.device_agent',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Original agent database owner command required' USING ERRCODE='42501';END IF;
 PERFORM device_compliance_receiving();action=command->>'action';source=command->'source';
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' FOR UPDATE;
 SELECT * INTO previous FROM device_agent_connections WHERE device_id=unit.id FOR UPDATE;
 IF unit.id IS NULL OR unit.tenant_id IS NULL THEN RAISE EXCEPTION 'Agent device unavailable' USING ERRCODE='42501';END IF;
 moment=clock_timestamp();next_state=previous;
 next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=coalesce(previous.revision,0)+1;
 IF action IN('issue','revoke') THEN
  deadline=(source->>'validUntil')::double precision;
  IF source->>'schemaVersion' IS DISTINCT FROM '1' OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
   OR source#>>'{tenant,id}' IS DISTINCT FROM unit.tenant_id::text OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
   OR deadline IS NULL OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::double precision OR deadline<=extract(epoch FROM moment)
   OR command->>'expectedRevision' IS DISTINCT FROM coalesce(previous.revision,0)::text OR length(command->>'reason') NOT BETWEEN 10 AND 500
   THEN RAISE EXCEPTION 'Original inventory authority and exact agent revision required' USING ERRCODE='42501';END IF;
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;next_state.credential_hash=NULL;next_state.credential_expires_at=NULL;
  next_state.revoked_at=moment;
  IF action='issue' THEN
   IF unit.platform NOT IN('windows','macos','linux') OR unit.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Available desktop platform required' USING ERRCODE='23514';END IF;
   next_state.bootstrap_hash=command->>'newHash';next_state.bootstrap_expires_at=moment+interval '10 minutes';
  END IF;
 ELSIF action='register' THEN
  deadline=extract(epoch FROM previous.bootstrap_expires_at);
  IF previous.bootstrap_hash IS NULL OR previous.bootstrap_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'One-time agent enrollment rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;
  next_state.credential_hash=command->>'newHash';next_state.credential_expires_at=moment+interval '90 days';next_state.enrolled_at=moment;next_state.revoked_at=NULL;
 ELSIF action='heartbeat' THEN
  deadline=extract(epoch FROM previous.credential_expires_at);
  IF previous.credential_hash IS NULL OR previous.credential_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR previous.revoked_at IS NOT NULL OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'Agent credential rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
 ELSE RAISE EXCEPTION 'Unsupported agent command' USING ERRCODE='42501';END IF;
 IF action IN('register','heartbeat') THEN
  next_state.last_seen=moment;next_state.hostname=command#>>'{report,hostname}';next_state.platform=command#>>'{report,platform}';
  next_state.architecture=command#>>'{report,architecture}';next_state.os_version=command#>>'{report,osVersion}';next_state.agent_version=command#>>'{report,agentVersion}';
  IF next_state.hostname IS NULL OR length(next_state.hostname) NOT BETWEEN 1 AND 255 OR length(next_state.architecture) NOT BETWEEN 1 AND 40
   OR length(next_state.os_version)>120 OR length(next_state.agent_version) NOT BETWEEN 1 AND 40 THEN RAISE EXCEPTION 'Bounded agent report required' USING ERRCODE='23514';END IF;
 END IF;
 IF command ? 'inventory' THEN
  IF action<>'heartbeat' OR NOT device_agent_inventory_valid(command->'inventory') THEN RAISE EXCEPTION 'Exact bounded agent inventory required' USING ERRCODE='23514';END IF;
  next_state.inventory_report=jsonb_build_object('schemaVersion',1,'facts',command->'inventory','receivedAt',moment,'enrolledAt',next_state.enrolled_at,'revision',next_state.revision::text,'platform',next_state.platform,'agentVersion',next_state.agent_version);
 END IF;
 IF command ? 'security' THEN
  IF action<>'heartbeat' OR NOT device_security_valid(command->'security') THEN RAISE EXCEPTION 'Exact security report required' USING ERRCODE='23514';END IF;
  next_state.security_report=jsonb_build_object('schemaVersion',1,'facts',command->'security','receivedAt',moment,'enrolledAt',next_state.enrolled_at,'revision',next_state.revision::text,'platform',next_state.platform,'agentVersion',next_state.agent_version);
  next_state.compliance_report=device_compliance_evaluate(next_state,moment);
  IF previous.compliance_report->>'fingerprint' IS DISTINCT FROM next_state.compliance_report->>'fingerprint' THEN
   compliance_event.id=(command->>'complianceEventId')::uuid;compliance_event.device_id=unit.id;compliance_event.tenant_id=unit.tenant_id;compliance_event.correlation_id=(command->>'correlationId')::uuid;compliance_event.created_at=moment;compliance_event.before_state=previous.compliance_report;compliance_event.after_state=next_state.compliance_report;
  END IF;
 END IF;
 IF deadline IS NULL OR deadline<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Agent deadline elapsed' USING ERRCODE='42501';END IF;
 IF action<>'heartbeat' THEN
  event.id=(command->>'eventId')::uuid;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.action=action;
  event.actor_user_id=(source->>'actorUserId')::uuid;event.reason=command->>'reason';event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;
  event.source=source;
  event.before_state=CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous)-ARRAY['bootstrap_hash','credential_hash'] END;
  event.after_state=to_jsonb(next_state)-ARRAY['bootstrap_hash','credential_hash'];
 END IF;
 envelope=jsonb_build_object('before',CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous) END,'after',to_jsonb(next_state),'event',CASE WHEN action='heartbeat' THEN NULL ELSE to_jsonb(event) END,'validUntil',deadline,'transactionId',txid_current()::text,'complianceEvent',CASE WHEN compliance_event.id IS NULL THEN NULL ELSE to_jsonb(compliance_event) END);
 PERFORM set_config('opendirectory.device_agent',envelope::text,true);
 IF previous.device_id IS NULL THEN INSERT INTO device_agent_connections SELECT next_state.*;
 ELSE UPDATE device_agent_connections SET (tenant_id,revision,bootstrap_hash,bootstrap_expires_at,credential_hash,credential_expires_at,enrolled_at,revoked_at,last_seen,hostname,platform,architecture,os_version,agent_version,inventory_report,security_report,compliance_report)=
  (next_state.tenant_id,next_state.revision,next_state.bootstrap_hash,next_state.bootstrap_expires_at,next_state.credential_hash,next_state.credential_expires_at,next_state.enrolled_at,next_state.revoked_at,next_state.last_seen,next_state.hostname,next_state.platform,next_state.architecture,next_state.os_version,next_state.agent_version,next_state.inventory_report,next_state.security_report,next_state.compliance_report) WHERE device_id=unit.id;END IF;
 IF action<>'heartbeat' THEN INSERT INTO device_agent_events SELECT event.*;END IF;
 IF compliance_event.id IS NOT NULL THEN INSERT INTO device_compliance_events SELECT compliance_event.*;END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_agent_connections;
BEGIN
 PERFORM device_compliance_receiving();
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 SELECT * INTO actual FROM device_agent_connections WHERE device_id=NEW.device_id;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  OR to_jsonb(actual) IS DISTINCT FROM proof->'after' OR NOT EXISTS(SELECT 1 FROM devices WHERE id=actual.device_id AND tenant_id=actual.tenant_id)
  OR (proof->'event'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_agent_events WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(device_agent_events)=proof->'event'))
  OR (proof->'complianceEvent'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_compliance_events event WHERE event.id=(proof#>>'{complianceEvent,id}')::uuid AND to_jsonb(event)=proof->'complianceEvent'))
  THEN RAISE EXCEPTION 'Actual agent effect and original deadline required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION device_compliance_current(UUID,TEXT,device_agent_connections,TIMESTAMPTZ),device_security_valid(JSONB),device_compliance_policy_valid(JSONB),device_compliance_receiving(),device_compliance_policy_change(JSONB),device_compliance_evaluate(device_agent_connections,TIMESTAMPTZ),device_agent_change(JSONB) FROM PUBLIC;
COMMIT;
