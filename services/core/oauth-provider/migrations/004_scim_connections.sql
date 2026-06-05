CREATE TABLE IF NOT EXISTS scim_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  provider VARCHAR(50) NOT NULL,
  endpoint TEXT,
  bearer_token_hash VARCHAR(512),
  sync_interval_minutes INTEGER DEFAULT 60,
  last_sync TIMESTAMPTZ,
  status VARCHAR(50) DEFAULT 'active',
  users_synced INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id UUID REFERENCES scim_connections(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  status VARCHAR(50) DEFAULT 'running',
  users_created INTEGER DEFAULT 0,
  users_updated INTEGER DEFAULT 0,
  users_deleted INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0,
  message TEXT
);

CREATE TABLE IF NOT EXISTS scim_conflicts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id UUID REFERENCES scim_connections(id),
  user_id VARCHAR(255),
  local_data JSONB,
  remote_data JSONB,
  conflict_type VARCHAR(100),
  resolved BOOLEAN DEFAULT false,
  resolution VARCHAR(50),
  created_at TIMESTAMPTZ DEFAULT NOW()
);
