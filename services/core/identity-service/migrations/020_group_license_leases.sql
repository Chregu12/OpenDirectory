CREATE OR REPLACE FUNCTION identity_group_snapshot_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
