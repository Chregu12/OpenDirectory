BEGIN;
ALTER TABLE group_members ADD COLUMN IF NOT EXISTS membership_id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS identity_membership_generation ON group_members(membership_id);
CREATE OR REPLACE FUNCTION identity_membership_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.membership_id := gen_random_uuid();
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_membership_generation ON group_members;
CREATE TRIGGER identity_membership_generation BEFORE INSERT ON group_members FOR EACH ROW EXECUTE FUNCTION identity_membership_generation();
COMMIT;
