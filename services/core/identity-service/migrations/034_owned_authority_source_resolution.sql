CREATE OR REPLACE FUNCTION identity_authority_source_observation(kind TEXT,identifier UUID,owner UUID,reviewed_at TIMESTAMPTZ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;audits JSONB;related JSONB='[]';relation TEXT;
BEGIN
 PERFORM identity_authority_owner();
 relation=CASE kind WHEN 'assignment' THEN 'identity_role_assignments' WHEN 'eligibility' THEN 'identity_pim_eligibilities' WHEN 'request' THEN 'identity_pim_requests' WHEN 'review' THEN 'identity_role_review_leases' END;
 IF relation IS NULL OR reviewed_at IS NULL OR NOT isfinite(reviewed_at) THEN RAISE EXCEPTION 'Exact bounded source observation required' USING ERRCODE='23514';END IF;
 EXECUTE format('SELECT to_jsonb(source) FROM %I source WHERE id=$1 AND identity_tenant_id(''user'',user_id)=$2',relation) INTO source USING identifier,owner;
 IF source IS NULL THEN RETURN NULL;END IF;
 IF kind='assignment' THEN
  SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_role_audit WHERE assignment_id=identifier ORDER BY created_at,id LIMIT 1001) evidence;
 ELSIF kind IN('eligibility','request') THEN
  SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_pim_audit WHERE entity_id=identifier ORDER BY created_at,id LIMIT 1001) evidence;
 ELSE
  SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_role_review_audit
   WHERE lease_id=identifier OR policy_id=(source->>'policy_id')::uuid AND lease_id IS NULL AND created_at<=reviewed_at ORDER BY created_at,id LIMIT 1001) evidence;
 END IF;
 IF jsonb_array_length(audits)>1000 THEN RAISE EXCEPTION 'Owned source evidence boundary exceeded' USING ERRCODE='54000';END IF;
 IF kind IN('assignment','eligibility') THEN
  SELECT COALESCE(jsonb_agg(jsonb_build_object('kind','review','id',id) ORDER BY id),'[]') INTO related FROM identity_role_review_leases WHERE target_kind=kind AND target_id=identifier;
  IF kind='assignment' AND source->'activation_request_id'<>'null'::jsonb THEN related=related||jsonb_build_array(jsonb_build_object('kind','request','id',source->>'activation_request_id'));END IF;
 ELSIF kind='request' THEN
  related=jsonb_build_array(jsonb_build_object('kind','eligibility','id',source->>'eligibility_id'))||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','assignment','id',id) ORDER BY id) FROM identity_role_assignments WHERE activation_request_id=identifier),'[]');
 ELSE related=jsonb_build_array(jsonb_build_object('kind',source->>'target_kind','id',source->>'target_id'));
 END IF;
 IF jsonb_array_length(related)>1000 THEN RAISE EXCEPTION 'Owned source graph boundary exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('state',identity_authority_state(source-ARRAY['reason','request_authority','decision_authority']),
  'beforeSha256',identity_authority_hash(jsonb_build_object('source',source,'audits',audits)),'relatedSources',related);
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_owned_role_evidence(identifier UUID,owner UUID,authority TEXT,recipient UUID) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE namespace identity_authority_namespaces;candidate identity_authority_candidates;tenant identity_tenants;account users;retained JSONB;links JSONB;canonical BOOLEAN;
 source JSONB;intention JSONB;observation JSONB;bindings JSONB='{}';entry JSONB;reference JSONB;reference_key TEXT;pending TEXT[];visited TEXT[];position INTEGER;
 assignment JSONB;state JSONB;profile JSONB;request JSONB;eligibility JSONB;target_key TEXT;eligibility_key TEXT;lease JSONB;old_rule JSONB;lease_count INTEGER;
 issue TEXT;cutoff TIMESTAMPTZ;due_epoch NUMERIC;review_cutoff NUMERIC;assignments JSONB='[]';grants JSONB='[]';roles JSONB;policies JSONB;fingerprint JSONB;result JSONB;
 observed TIMESTAMPTZ;recipient_active BOOLEAN;required BOOLEAN;max_age INTEGER;amount INTEGER=0;owned_profiles JSONB;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier AND tenant_id=owner AND issuer=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority namespace not found' USING ERRCODE='23503';END IF;
 IF namespace.transaction_id=txid_current() THEN RAISE EXCEPTION 'A committed sealed namespace is required' USING ERRCODE='42501';END IF;
 SELECT * INTO account FROM users WHERE id=recipient AND identity_tenant_id('user',id)=owner;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned bound recipient not found' USING ERRCODE='23503';END IF;
 PERFORM identity_authority_namespace_receiving();PERFORM identity_authority_namespace_receipt(identifier);
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=namespace.candidate_id;
 SELECT * INTO tenant FROM identity_tenants WHERE id=owner;
 IF NOT tenant.enabled OR tenant.version<>namespace.tenant_version OR tenant.generation<>namespace.tenant_generation OR namespace.publication_deadline<=clock_timestamp()
  THEN RAISE EXCEPTION 'Current sealed authority incarnation required' USING ERRCODE='42501';END IF;
 SELECT jsonb_agg(jsonb_build_object('role',head.role,'authenticationVersion',authentication.version::text,'activationVersion',activation.version::text,'reviewVersion',review.version::text,
  'authentication',jsonb_build_object('required',authentication.required,'maxAgeSeconds',authentication.max_age_seconds),
  'activation',jsonb_build_object('required',activation.required,'maxDurationSeconds',activation.max_duration_seconds,'reviewerUserIds',to_jsonb(activation.reviewer_user_ids)),
  'review',CASE WHEN review.required THEN jsonb_build_object('intervalSeconds',review.interval_seconds,'windowSeconds',review.window_seconds,'reviewerUserIds',to_jsonb(review.reviewer_user_ids)) ELSE 'null'::jsonb END) ORDER BY head.role COLLATE "C") INTO owned_profiles
 FROM identity_owned_role_policies head
 JOIN identity_owned_role_authentication authentication ON authentication.namespace_id=head.namespace_id AND authentication.role=head.role AND authentication.version=head.authentication_version
 JOIN identity_owned_role_activation activation ON activation.namespace_id=head.namespace_id AND activation.role=head.role AND activation.version=head.activation_version
 JOIN identity_owned_role_reviews review ON review.namespace_id=head.namespace_id AND review.role=head.role AND review.version=head.review_version
 WHERE head.namespace_id=identifier AND head.tenant_id=owner;
 SELECT value INTO retained FROM jsonb_array_elements(candidate.inventory->'users') WHERE value->>'id'=recipient::text;
 IF retained IS NULL THEN RAISE EXCEPTION 'Owned bound recipient not found' USING ERRCODE='23503';END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(link) ORDER BY link.issuer,link.subject),'[]') INTO links FROM (SELECT * FROM identity_subject_links WHERE user_id=recipient ORDER BY issuer,subject LIMIT 1001) link;
 IF jsonb_array_length(links)>1000 THEN RAISE EXCEPTION 'Owned source link boundary exceeded' USING ERRCODE='54000';END IF;
 SELECT EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=owner WHERE link.user_id=recipient AND link.issuer=authority) INTO canonical;
 recipient_active=account.enabled AND canonical AND account.tenant_generation::text=retained->>'tenantGeneration';observed=clock_timestamp();
 FOR source IN SELECT value FROM jsonb_array_elements(candidate.inventory->'sources') WHERE value->>'userId'=recipient::text ORDER BY value->>'kind',value->>'id' LOOP
  SELECT value INTO intention FROM jsonb_array_elements(candidate.manifest->'sources') WHERE value->>'kind'=source->>'kind' AND value->>'id'=source->>'id';
  observation=identity_authority_source_observation(source->>'kind',(source->>'id')::uuid,owner,candidate.created_at);
  entry=source||jsonb_build_object('disposition',intention->>'disposition','matches',COALESCE(observation->'state'=source->'state' AND observation->'beforeSha256'=source->'beforeSha256' AND observation->'relatedSources'=source->'relatedSources',false),
   'acceptedOrigin',source->>'origin'='canonical-home-coherent' OR source->>'origin'='offline-review-required' AND intention->'acceptOfflineOrigin'='true'::jsonb);
  bindings=jsonb_set(bindings,ARRAY[(source->>'kind')||':'||(source->>'id')],entry);
 END LOOP;
 FOR assignment IN SELECT value FROM jsonb_each(bindings) WHERE value->>'kind'='assignment' ORDER BY key COLLATE "C" LOOP
  state=assignment->'state';issue=NULL;request=NULL;eligibility=NULL;eligibility_key=NULL;cutoff=namespace.publication_deadline;
  pending=ARRAY['assignment:'||(assignment->>'id')];visited='{}';position=1;
  SELECT value INTO profile FROM jsonb_array_elements(owned_profiles) WHERE value->>'role'=assignment->>'role';
  WHILE position<=cardinality(pending) LOOP
   entry=bindings->pending[position];visited=array_append(visited,pending[position]);position=position+1;
   IF entry IS NULL OR entry->>'userId' IS DISTINCT FROM recipient::text OR entry->>'role' IS DISTINCT FROM assignment->>'role' THEN issue='incoherent_component';EXIT;END IF;
   IF entry->>'disposition' IS DISTINCT FROM 'adopt' THEN issue='quarantined_component';EXIT;END IF;
   IF entry->'acceptedOrigin' IS DISTINCT FROM 'true'::jsonb OR entry->'live' IS DISTINCT FROM 'true'::jsonb THEN issue='unavailable_component';EXIT;END IF;
   IF entry->'matches' IS DISTINCT FROM 'true'::jsonb THEN issue='source_changed';EXIT;END IF;
   FOR reference IN SELECT value FROM jsonb_array_elements(entry->'relatedSources') LOOP
    reference_key=(reference->>'kind')||':'||(reference->>'id');
    IF NOT reference_key=ANY(pending) THEN pending=array_append(pending,reference_key);END IF;
   END LOOP;
   IF cardinality(pending)>1000 THEN RAISE EXCEPTION 'Owned component boundary exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
  IF issue IS NULL AND NOT recipient_active THEN issue='recipient_unavailable';END IF;
  IF issue IS NULL AND (state->>'role' IS DISTINCT FROM assignment->>'role' OR state->'revoked_at'<>'null'::jsonb OR profile IS NULL) THEN issue='assignment_unavailable';END IF;
  IF issue IS NULL THEN
   IF (state->>'created_at')::timestamptz>observed OR state->'expires_at'<>'null'::jsonb AND ((state->>'expires_at')::timestamptz<=observed OR (state->>'expires_at')::timestamptz<=(state->>'created_at')::timestamptz) THEN issue='assignment_expired';
   ELSIF assignment->>'role'<>'user' AND (state->'expires_at'='null'::jsonb OR extract(epoch FROM (state->>'expires_at')::timestamptz-(state->>'created_at')::timestamptz)>(profile->'activation'->>'maxDurationSeconds')::integer) THEN issue='duration_requires_new_grant';
   ELSE cutoff=least(cutoff,(state->>'expires_at')::timestamptz);END IF;
  END IF;
  IF issue IS NULL AND profile->'activation'->'required'='true'::jsonb AND state->'activation_request_id'='null'::jsonb THEN issue='owned_activation_required';END IF;
  IF issue IS NULL AND state->'activation_request_id'<>'null'::jsonb THEN
   request=bindings->('request:'||(state->>'activation_request_id'));eligibility_key='eligibility:'||(request->'state'->>'eligibility_id');eligibility=bindings->eligibility_key;
   IF request IS NULL OR eligibility IS NULL OR NOT ('request:'||(request->>'id'))=ANY(visited) OR NOT eligibility_key=ANY(visited)
    OR request->'state'->>'state'<>'active' OR request->'state'->>'user_id' IS DISTINCT FROM recipient::text OR eligibility->'state'->>'user_id' IS DISTINCT FROM recipient::text
    OR eligibility->'state'->>'role' IS DISTINCT FROM assignment->>'role' OR eligibility->'state'->'revoked_at'<>'null'::jsonb
    OR request->'state'->'policy_version' IS DISTINCT FROM state->'policy_version'
    OR (request->'state'->>'duration_seconds')::integer>(profile->'activation'->>'maxDurationSeconds')::integer
    OR (request->'state'->>'duration_seconds')::integer>(eligibility->'state'->>'max_duration_seconds')::integer THEN issue='owned_activation_unavailable';
   ELSIF (eligibility->'state'->>'expires_at')::timestamptz<=observed OR (state->>'expires_at')::timestamptz>(eligibility->'state'->>'expires_at')::timestamptz
    OR extract(epoch FROM (state->>'expires_at')::timestamptz-(state->>'created_at')::timestamptz)>(request->'state'->>'duration_seconds')::integer THEN issue='owned_activation_expired';
   ELSE cutoff=least(cutoff,(eligibility->'state'->>'expires_at')::timestamptz);END IF;
  END IF;
  IF issue IS NULL THEN
   FOREACH target_key IN ARRAY ARRAY['assignment:'||(assignment->>'id'),eligibility_key] LOOP
    IF target_key IS NULL THEN CONTINUE;END IF;
    SELECT count(*),jsonb_agg(value ORDER BY key) INTO lease_count,lease FROM jsonb_each(bindings) WHERE key=ANY(visited) AND value->>'kind'='review'
     AND (value->'state'->>'target_kind')||':'||(value->'state'->>'target_id')=target_key;
    IF lease_count>1 THEN issue='incoherent_review';EXIT;END IF;
    lease=lease->0->'state';
    IF profile->'review'<>'null'::jsonb AND (lease IS NULL OR lease->>'state'<>'pending') THEN issue='owned_review_required';EXIT;END IF;
    IF lease IS NOT NULL THEN
     IF lease->>'state' NOT IN('pending','exempt') THEN issue='owned_review_unavailable';EXIT;END IF;
     IF lease->>'state'='pending' THEN
      due_epoch=extract(epoch FROM (lease->>'due_at')::timestamptz);review_cutoff=extract(epoch FROM (lease->>'deadline_at')::timestamptz);
      IF profile->'review'<>'null'::jsonb THEN
       SELECT value INTO old_rule FROM jsonb_array_elements(candidate.inventory->'reviewPolicies') WHERE value->>'id'=lease->>'policy_id' AND value->>'role'=assignment->>'role' AND value->'retired'='false'::jsonb;
       IF old_rule IS NULL THEN issue='owned_review_unavailable';EXIT;END IF;
       due_epoch=due_epoch-greatest(0,(old_rule->>'intervalSeconds')::integer-(profile->'review'->>'intervalSeconds')::integer)::numeric*((lease->>'cycle')::numeric-1);
       review_cutoff=least(review_cutoff,due_epoch+(profile->'review'->>'windowSeconds')::integer);
      END IF;
      IF review_cutoff<=extract(epoch FROM observed) THEN issue='owned_review_expired';EXIT;END IF;
      cutoff=least(cutoff,to_timestamp(review_cutoff::double precision));
     ELSIF lease->'due_at'<>'null'::jsonb OR lease->'deadline_at'<>'null'::jsonb THEN issue='owned_review_unavailable';EXIT;
     END IF;
    END IF;
   END LOOP;
  END IF;
  IF issue IS NULL AND cutoff<=clock_timestamp() THEN issue='source_expired';END IF;
  assignments=assignments||jsonb_build_array(jsonb_build_object('id',assignment->>'id','role',assignment->>'role','eligibleForAdoption',issue IS NULL,'issue',issue));
  IF issue IS NULL THEN
   amount=amount+1;IF amount>100 THEN RAISE EXCEPTION 'Owned positive assignment boundary exceeded' USING ERRCODE='54000';END IF;
   grants=grants||jsonb_build_array(jsonb_build_object('id',assignment->>'id','role',assignment->>'role','validUntil',cutoff,
    'authenticationVersion',profile->>'authenticationVersion','activationVersion',profile->>'activationVersion','reviewVersion',profile->>'reviewVersion','sources',(SELECT jsonb_agg(jsonb_build_array(key,value->>'beforeSha256') ORDER BY key COLLATE "C") FROM jsonb_each(bindings) WHERE key=ANY(visited))));
  END IF;
 END LOOP;
 SELECT COALESCE(jsonb_agg(role ORDER BY role COLLATE "C"),'[]') INTO roles FROM (SELECT DISTINCT value->>'role' AS role FROM jsonb_array_elements(grants)) held;
 SELECT COALESCE(jsonb_agg(setting.value ORDER BY setting.value->>'role' COLLATE "C"),'[]'),COALESCE(bool_or((setting.value->'authentication'->>'required')::boolean),false),
  COALESCE(min((setting.value->'authentication'->>'maxAgeSeconds')::integer) FILTER(WHERE setting.value->'authentication'->'required'='true'::jsonb),86400) INTO policies,required,max_age FROM jsonb_array_elements(owned_profiles) setting WHERE roles ? (setting.value->>'role');
 fingerprint=jsonb_build_array('owned-authority-sealed-evidence-v1',identifier,namespace.generation::text,owner,tenant.version::text,tenant.generation::text,authority,
  recipient,account.authorization_revision::text,account.eligibility_revision::text,account.tenant_generation::text,identity_authority_hash(links),grants,policies);
 SELECT least(namespace.publication_deadline,min((value->>'validUntil')::timestamptz)) INTO cutoff FROM jsonb_array_elements(grants);
 IF namespace.publication_deadline<=clock_timestamp() THEN RAISE EXCEPTION 'Current sealed authority incarnation required' USING ERRCODE='42501';END IF;
 result=jsonb_build_object('schemaVersion',1,'canAuthorize',false,'state','sealed','namespaceId',identifier,'namespaceGeneration',namespace.generation::text,
  'tenant',jsonb_build_object('id',owner,'version',tenant.version::text,'generation',tenant.generation::text),'issuer',authority,'userId',recipient,'recipientActive',recipient_active,
  'proposedRoles',roles,'authentication',jsonb_build_object('required',required,'maxAgeSeconds',max_age),'proposedRolesRevision',identity_authority_hash(fingerprint),'assignments',assignments,'grants',grants,'validUntil',cutoff);
 RETURN result;
END; $$;

DO $$ DECLARE routine TEXT;BEGIN
 FOREACH routine IN ARRAY ARRAY['identity_authority_source_observation(text,uuid,uuid,timestamptz)','identity_authority_owned_role_evidence(uuid,uuid,text,uuid)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
