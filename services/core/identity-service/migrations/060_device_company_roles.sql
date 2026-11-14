BEGIN;
DO $$ DECLARE entry RECORD;BEGIN
 FOR entry IN SELECT conname FROM pg_constraint WHERE conrelid='identity_company_roles'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%cardinality(permissions)%' LOOP
  EXECUTE format('ALTER TABLE identity_company_roles DROP CONSTRAINT %I',entry.conname);
 END LOOP;
END; $$;
ALTER TABLE identity_company_roles ADD CONSTRAINT identity_company_role_permissions CHECK(
 cardinality(permissions)>0 AND permissions<@ARRAY[
 'users.read','users.create','users.update','users.status.manage','groups.read','groups.create','groups.update','groups.delete','groups.members.manage',
 'ous.read','ous.create','ous.update','ous.delete','ous.members.manage',
 'devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read','devices.compliance.manage']::text[]
 AND (NOT permissions&&ARRAY['devices.inventory.create','devices.inventory.assign']::text[] OR 'devices.inventory.read'=ANY(permissions))
 AND (NOT 'devices.compliance.manage'=ANY(permissions) OR 'devices.compliance.read'=ANY(permissions))
);
COMMIT;
