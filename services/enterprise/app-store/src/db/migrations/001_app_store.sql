CREATE TABLE IF NOT EXISTS store_apps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  description TEXT,
  category VARCHAR(100) NOT NULL,
  publisher VARCHAR(255),
  icon_url TEXT,
  homepage_url TEXT,
  version VARCHAR(50) NOT NULL,
  platforms JSONB NOT NULL DEFAULT '[]', -- ["windows","macos","linux"]
  packages JSONB NOT NULL DEFAULT '{}',
  -- packages structure: { "windows": { "type": "winget", "id": "Mozilla.Firefox", "args": "--silent" },
  --                        "macos": { "type": "brew", "id": "firefox", "cask": true },
  --                        "linux": { "type": "apt", "id": "firefox" } }
  size_bytes BIGINT,
  license_type VARCHAR(50) DEFAULT 'free', -- free, commercial, enterprise
  max_licenses INTEGER,
  used_licenses INTEGER DEFAULT 0,
  required BOOLEAN DEFAULT false, -- mandatory app
  tags JSONB DEFAULT '[]',
  metadata JSONB DEFAULT '{}',
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS store_app_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID REFERENCES store_apps(id) ON DELETE CASCADE,
  version VARCHAR(50) NOT NULL,
  changelog TEXT,
  packages JSONB NOT NULL DEFAULT '{}',
  release_date TIMESTAMPTZ DEFAULT NOW(),
  min_os_version JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS store_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID REFERENCES store_apps(id) ON DELETE CASCADE,
  target_type VARCHAR(50) NOT NULL, -- ou, group, domain, device, user
  target_id VARCHAR(255) NOT NULL,
  target_name VARCHAR(255),
  install_type VARCHAR(20) DEFAULT 'available', -- required, available, uninstall
  created_at TIMESTAMPTZ DEFAULT NOW(),
  created_by VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS store_installations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID REFERENCES store_apps(id),
  device_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255),
  version VARCHAR(50),
  status VARCHAR(30) DEFAULT 'pending', -- pending, downloading, installing, installed, failed, uninstalling, uninstalled
  progress INTEGER DEFAULT 0,
  error_message TEXT,
  installed_at TIMESTAMPTZ,
  requested_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS store_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL,
  icon VARCHAR(50),
  sort_order INTEGER DEFAULT 0,
  parent_id UUID REFERENCES store_categories(id)
);

-- Seed categories
INSERT INTO store_categories (name, display_name, icon, sort_order) VALUES
  ('productivity', 'Produktivitaet', 'briefcase', 1),
  ('security', 'Sicherheit', 'shield', 2),
  ('development', 'Entwicklung', 'code', 3),
  ('communication', 'Kommunikation', 'chat', 4),
  ('media', 'Medien & Design', 'photo', 5),
  ('utilities', 'Werkzeuge', 'wrench', 6),
  ('browser', 'Browser', 'globe', 7),
  ('system', 'System', 'cog', 8)
ON CONFLICT (name) DO NOTHING;

CREATE INDEX idx_store_apps_category ON store_apps(category);
CREATE INDEX idx_store_apps_platforms ON store_apps USING gin(platforms);
CREATE INDEX idx_store_assignments_target ON store_assignments(target_type, target_id);
CREATE INDEX idx_store_installations_device ON store_installations(device_id);
CREATE INDEX idx_store_installations_status ON store_installations(status);
