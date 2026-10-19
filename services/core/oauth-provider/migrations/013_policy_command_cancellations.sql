BEGIN;
CREATE OR REPLACE FUNCTION policy_device_cancellation_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS $$ SELECT 1; $$;
CREATE TABLE IF NOT EXISTS policy_device_cancellations (
 command_id VARCHAR(255) PRIMARY KEY REFERENCES mdm_commands(id),operation_id UUID NOT NULL UNIQUE,
 actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 original_receipt JSONB NOT NULL,audit_id UUID NOT NULL UNIQUE REFERENCES policy_device_command_audit(id),
 previously_offered_at TIMESTAMPTZ,cancelled_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE policy_device_command_audit DROP CONSTRAINT IF EXISTS policy_device_command_audit_action_check;
ALTER TABLE policy_device_command_audit ADD CONSTRAINT policy_device_command_audit_action_check CHECK(action IN('queued','dispatched','reported','cancelled'));
CREATE OR REPLACE FUNCTION policy_device_receipt(command mdm_commands) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('schemaVersion',1,'commandId',command.id,'operationId',command.policy_operation_id,'deviceId',command.device_id,
 'deviceGeneration',command.policy_generation::text,'operatorUserId',command.policy_actor->>'userId','reference',command.policy_context->'reference',
 'configurationVersion',command.policy_context->'configurationVersion','configurationHash',command.policy_context->'configurationHash',
 'publicationVersion',command.policy_context->'publicationVersion','payloadHash',command.policy_context->'payloadHash',
 'expiresAt',to_char(command.policy_delivery_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'persistence','committed');
$$;
CREATE OR REPLACE FUNCTION policy_device_cancellation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;actor JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_device_command',true),'')::jsonb;actor=proof->'actor';
 PERFORM id FROM enrolled_devices WHERE id=OLD.device_id FOR UPDATE;
 IF OLD.command<>'update_policy' OR OLD.policy_context IS NULL OR OLD.status<>'pending' OR NEW.status<>'cancelled'
  OR proof->>'action' IS DISTINCT FROM 'cancelled' OR proof->>'commandId' IS DISTINCT FROM OLD.id OR NOT policy_device_user_fresh(actor)
  OR actor->>'userId' IS DISTINCT FROM OLD.policy_actor->>'userId'
  OR NOT COALESCE(proof->>'operationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
  OR proof->'receipt' IS DISTINCT FROM policy_device_receipt(OLD)
  OR NOT COALESCE(jsonb_typeof(proof->'reason')='string' AND length(proof->>'reason') BETWEEN 10 AND 500 AND proof->>'reason'=btrim(proof->>'reason'),false)
  THEN RAISE EXCEPTION 'Exact owned pending policy command cancellation required' USING ERRCODE='42501';END IF;
 IF (to_jsonb(NEW)-ARRAY['status','policy_version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','policy_version'])
  OR OLD.policy_version>=2147483647 THEN RAISE EXCEPTION 'Cancellation preserves command and device evidence' USING ERRCODE='23514';END IF;
 NEW.policy_version=OLD.policy_version+1;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_cancellation_recorded() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;event policy_device_command_audit%ROWTYPE;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_device_command',true),'')::jsonb;
 SELECT * INTO event FROM policy_device_command_audit WHERE command_id=NEW.id AND version=NEW.policy_version;
 IF event.action IS DISTINCT FROM 'cancelled' OR event.actor IS DISTINCT FROM proof->'actor' THEN RAISE EXCEPTION 'Cancellation audit required' USING ERRCODE='23514';END IF;
 INSERT INTO policy_device_cancellations(command_id,operation_id,actor,reason,original_receipt,audit_id,previously_offered_at,cancelled_at)
 VALUES(NEW.id,(proof->>'operationId')::uuid,event.actor,proof->>'reason',policy_device_receipt(NEW),event.id,OLD.policy_dispatched_at,event.created_at);
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_cancellation_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE retained policy_device_cancellations%ROWTYPE;
BEGIN
 SELECT * INTO retained FROM policy_device_cancellations WHERE command_id=NEW.id;
 IF retained.command_id IS NULL OR retained.original_receipt IS DISTINCT FROM policy_device_receipt(NEW)
  THEN RAISE EXCEPTION 'Retained cancellation required' USING ERRCODE='23514';END IF;
 IF (retained.actor->>'expiresAt')::numeric<=floor(EXTRACT(epoch FROM policy_device_now()))
  THEN RAISE EXCEPTION 'Cancellation credential expired' USING ERRCODE='23514',CONSTRAINT='policy_device_token_expired';END IF;
 IF NOT policy_device_user_fresh(retained.actor)
  THEN RAISE EXCEPTION 'Cancellation MFA expired' USING ERRCODE='23514',CONSTRAINT='policy_device_mfa_expired';END IF;
 RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS policy_device_command_guard ON mdm_commands;
CREATE TRIGGER policy_device_command_guard BEFORE INSERT OR DELETE ON mdm_commands FOR EACH ROW EXECUTE FUNCTION policy_device_command_guard();
DROP TRIGGER IF EXISTS policy_device_command_update_guard ON mdm_commands;
CREATE TRIGGER policy_device_command_update_guard BEFORE UPDATE ON mdm_commands FOR EACH ROW
 WHEN(OLD.command IS DISTINCT FROM 'update_policy' OR (OLD.status IS DISTINCT FROM 'cancelled' AND NEW.status IS DISTINCT FROM 'cancelled')) EXECUTE FUNCTION policy_device_command_guard();
DROP TRIGGER IF EXISTS policy_device_cancellation_guard ON mdm_commands;
CREATE TRIGGER policy_device_cancellation_guard BEFORE UPDATE ON mdm_commands FOR EACH ROW
 WHEN(OLD.command='update_policy' AND (OLD.status='cancelled' OR NEW.status='cancelled')) EXECUTE FUNCTION policy_device_cancellation_guard();
DROP TRIGGER IF EXISTS policy_device_command_stopped ON mdm_commands;
CREATE TRIGGER policy_device_command_stopped AFTER UPDATE ON mdm_commands FOR EACH ROW
 WHEN(NEW.command='update_policy' AND NEW.status='cancelled') EXECUTE FUNCTION policy_device_cancellation_recorded();
DROP TRIGGER IF EXISTS policy_device_command_commit_guard ON mdm_commands;
CREATE CONSTRAINT TRIGGER policy_device_command_commit_guard AFTER INSERT OR UPDATE ON mdm_commands DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN(NOT(NEW.command='update_policy' AND NEW.status='cancelled')) EXECUTE FUNCTION policy_device_command_commit_guard();
DROP TRIGGER IF EXISTS policy_device_cancellation_commit_guard ON mdm_commands;
CREATE CONSTRAINT TRIGGER policy_device_cancellation_commit_guard AFTER UPDATE ON mdm_commands DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN(NEW.command='update_policy' AND NEW.status='cancelled') EXECUTE FUNCTION policy_device_cancellation_commit_guard();
DROP TRIGGER IF EXISTS policy_device_evidence_guard ON policy_device_cancellations;
CREATE TRIGGER policy_device_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_device_cancellations FOR EACH ROW EXECUTE FUNCTION policy_device_evidence_guard();
COMMIT;
