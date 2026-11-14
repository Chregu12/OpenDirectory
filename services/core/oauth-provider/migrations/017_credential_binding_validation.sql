-- Repair existing installations as well as fresh migration replay.
CREATE OR REPLACE FUNCTION oauth_valid_credential_authorization(input_value JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE revision TEXT;
BEGIN
  IF input_value IS NULL THEN RETURN TRUE; END IF;
  IF jsonb_typeof(input_value)<>'object' THEN RETURN FALSE; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(input_value))<>5
    OR NOT (input_value ?& ARRAY['schemaVersion','subjectId','userId','invitationId','securityRevision'])
    OR input_value->'schemaVersion'<>'1'::jsonb
    OR input_value->>'subjectId' IS NULL
    OR input_value->>'subjectId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    OR input_value->>'userId' IS NULL
    OR input_value->>'userId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    OR (jsonb_typeof(input_value->'invitationId')<>'null' AND
      (jsonb_typeof(input_value->'invitationId')<>'string' OR input_value->>'invitationId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'))
    OR jsonb_typeof(input_value->'securityRevision')<>'string' THEN RETURN FALSE; END IF;
  revision:=input_value->>'securityRevision';
  IF revision IS NULL OR revision !~ '^[1-9][0-9]{0,18}$' THEN RETURN FALSE; END IF;
  RETURN revision::numeric<=9223372036854775807;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END $$;
