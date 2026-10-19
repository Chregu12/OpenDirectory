ALTER TABLE license_group_observations ADD COLUMN IF NOT EXISTS source_authorization JSONB;
ALTER TABLE license_group_observations ADD COLUMN IF NOT EXISTS source_authorization_deadline TIMESTAMPTZ;
CREATE OR REPLACE FUNCTION license_group_source_authorization_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;consent JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.group_snapshot',true),'')::jsonb;consent=NULLIF(proof->'sourceAuthorization','null'::jsonb);
 IF proof->>'schemaVersion' IS DISTINCT FROM '3' OR NOT(proof?'sourceAuthorization') OR NEW.source_authorization IS DISTINCT FROM consent
  OR NEW.source_authorization_deadline IS DISTINCT FROM (consent->>'expiresAt')::timestamptz
  OR consent IS NOT NULL AND (jsonb_typeof(consent)<>'object' OR CASE WHEN jsonb_typeof(consent)='object' THEN (SELECT count(*) FROM jsonb_object_keys(consent)) ELSE 0 END<>6 OR COALESCE(consent->>'grantId','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
   OR COALESCE(consent->>'version','') !~ '^[1-9][0-9]{0,18}$' OR (consent->>'version')::numeric>9223372036854775807
   OR COALESCE(consent->>'clientRevision','') !~ '^[1-9][0-9]{0,18}$' OR (consent->>'clientRevision')::numeric>9223372036854775807
   OR COALESCE(consent->>'clientId','') !~ '^[A-Za-z0-9._~-]{1,255}$' OR consent->>'clientId' IN('.','..') OR COALESCE(consent->>'issuer','')='' OR NEW.source_authorization_deadline<=license_now())
  THEN RAISE EXCEPTION 'Exact live source authorization required' USING ERRCODE='23514',CONSTRAINT='license_group_directory_lease';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_group_source_authorization_guard ON license_group_observations;
CREATE TRIGGER license_group_source_authorization_guard BEFORE INSERT OR UPDATE ON license_group_observations FOR EACH ROW EXECUTE FUNCTION license_group_source_authorization_guard();
DO $$ DECLARE definition TEXT;BEGIN
 definition=pg_get_functiondef('license_group_lease_guard()'::regprocedure);
 definition=replace(definition,$pattern$proof->>'schemaVersion' IS DISTINCT FROM '2'$pattern$,$replacement$proof->>'schemaVersion' IS DISTINCT FROM '3'$replacement$);
 definition=replace(definition,'LEAST(observation.valid_until,NEW.review_deadline_at)','LEAST(observation.valid_until,observation.source_authorization_deadline,NEW.review_deadline_at)');EXECUTE definition;
 definition=pg_get_functiondef('license_group_lease_commit_guard()'::regprocedure);
 IF position('source_authorization_deadline' in definition)=0 THEN
  definition=replace(definition,'NEW.valid_until<=license_now()', $replacement$(NEW.valid_until<=license_now() OR (to_jsonb(NEW)->>'source_authorization_deadline')::timestamptz<=license_now())$replacement$);EXECUTE definition;
 END IF;
END; $$;
