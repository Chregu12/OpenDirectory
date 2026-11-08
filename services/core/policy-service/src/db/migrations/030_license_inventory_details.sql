-- Keep private procurement references outside immutable company catalog receipts.
CREATE TABLE IF NOT EXISTS license_inventory_details (
  license_id UUID PRIMARY KEY REFERENCES license_catalog(id) ON DELETE CASCADE,
  details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);
