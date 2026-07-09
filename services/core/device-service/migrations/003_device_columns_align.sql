-- 003_device_columns_align.sql
--
-- PostgresDeviceRepository.save()/findAll()/findById() (the DDD aggregate
-- persistence path used by DeviceAggregate / IDeviceRepository, i.e.
-- POST /api/devices -> createDevice -> repository.save()) reads and writes
-- columns hostname, is_compliant and compliance_violations. These map 1:1
-- to DeviceAggregate's hostname / isCompliant / complianceViolations
-- fields (see DeviceAggregate.toJSON()).
--
-- 001_devices.sql never created these columns — it only has the legacy
-- "name" / "compliance_status" columns used by the upsertDevice()/getDevice()
-- helper methods (the pre-DDD CRUD path used by index.js route handlers
-- other than the aggregate path). Both persistence paths share the same
-- `devices` table, so the table needs both sets of columns.
--
-- Decision: the code (DeviceAggregate + PostgresDeviceRepository) is treated
-- as the source of truth; this migration brings the schema in line with it
-- additively, without touching the existing legacy columns.
--
-- Note on NOT NULL: `name` (from 001) has no NOT NULL constraint, and
-- save()'s INSERT does not set it — that's fine, it will simply be NULL for
-- rows created via the aggregate path. No existing NOT NULL column is left
-- unfilled by save()'s INSERT list (id, hostname, platform, status,
-- is_compliant, compliance_violations, last_seen, enrolled_at, os,
-- os_version, ip_address, kernel, package_manager), so no nullability
-- changes are required elsewhere.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_compliant BOOLEAN DEFAULT true;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS compliance_violations JSONB DEFAULT '[]';
