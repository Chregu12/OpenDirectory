# ─────────────────────────────────────────────────────────────────────────────
# OpenDirectory Terraform Provider — Example Configuration
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    opendirectory = {
      source  = "opendirectory/opendirectory"
      version = "~> 1.0"
    }
  }
  required_version = ">= 1.3"
}

# ── Variables ────────────────────────────────────────────────────────────────

variable "od_api_url" {
  description = "OpenDirectory API URL"
  type        = string
  default     = "https://od.example.com"
}

variable "od_api_key" {
  description = "OpenDirectory API key"
  type        = string
  sensitive   = true
}

# ── Provider ─────────────────────────────────────────────────────────────────

provider "opendirectory" {
  api_url = var.od_api_url
  api_key = var.od_api_key
  timeout = 30
}

# ── Groups ───────────────────────────────────────────────────────────────────

resource "opendirectory_group" "engineering" {
  name        = "Engineering"
  description = "Engineering department devices and users"
  type        = "static"
}

# ── Users ────────────────────────────────────────────────────────────────────

resource "opendirectory_user" "admin" {
  username  = "admin"
  email     = "admin@example.com"
  full_name = "Platform Admin"
  role      = "admin"
  group_ids = [opendirectory_group.engineering.id]
}

# ── Security Baseline Policy ────────────────────────────────────────────────

resource "opendirectory_policy" "security_baseline" {
  name        = "Security Baseline"
  description = "Enforces security baseline across all managed devices"
  type        = "security"
  priority    = 10
  enabled     = true

  rules_json = jsonencode({
    firewall_enabled    = true
    encryption_required = true
    min_password_length = 12
    screen_lock_timeout = 300
    auto_update_enabled = true
  })

  targets = [opendirectory_group.engineering.id]
}

# ── Certificate for WiFi EAP-TLS ────────────────────────────────────────────

resource "opendirectory_certificate" "wifi_cert" {
  common_name       = "wifi-client.example.com"
  organization      = "Example Corp"
  organization_unit = "IT"
  country           = "US"
  key_type          = "RSA"
  key_size          = 2048
  validity_days     = 365
  usage             = "client"
  sans              = "wifi-client.example.com"
}

# ── Managed Device ───────────────────────────────────────────────────────────

resource "opendirectory_device" "macbook_eng_01" {
  name          = "macbook-eng-01"
  hostname      = "macbook-eng-01.local"
  platform      = "macos"
  os_version    = "14.3"
  serial_number = "C02Z1234ABCD"
  model         = "MacBookPro18,1"
  owner         = opendirectory_user.admin.id
  group_id      = opendirectory_group.engineering.id
  tags          = ["engineering", "laptop"]
}

# ── Corporate WiFi Profile ──────────────────────────────────────────────────

resource "opendirectory_wifi_profile" "corporate_wifi" {
  device_id      = opendirectory_device.macbook_eng_01.id
  name           = "Corporate WiFi"
  ssid           = "Corp-Secure"
  security_type  = "WPA2Enterprise"
  auto_join      = true
  hidden         = false
  eap_type       = "TLS"
  certificate_id = opendirectory_certificate.wifi_cert.id
}

# ── Corporate VPN Profile ───────────────────────────────────────────────────

resource "opendirectory_vpn_profile" "corporate_vpn" {
  device_id        = opendirectory_device.macbook_eng_01.id
  name             = "Corporate VPN"
  vpn_type         = "IKEv2"
  server           = "vpn.example.com"
  remote_id        = "vpn.example.com"
  local_id         = "macbook-eng-01"
  on_demand_enabled = true
  on_demand_rules  = jsonencode({
    action           = "connect"
    interface_match  = "WiFi"
    ssid_match       = ["Corp-Secure"]
  })
}

# ── OS Update Policy ────────────────────────────────────────────────────────

resource "opendirectory_update_policy" "standard_updates" {
  device_id          = opendirectory_device.macbook_eng_01.id
  name               = "Standard macOS Updates"
  auto_update        = true
  maintenance_window = "Sun 02:00-06:00"
  deferral_days      = 3
  force_restart      = false
  allow_user_defer   = true
  max_deferrals      = 5
  include_beta       = false
  allowed_versions   = ">=14.0 <16.0"
}

# ── Data Sources ─────────────────────────────────────────────────────────────

data "opendirectory_devices" "macos_fleet" {
  platform = "macos"
  status   = "active"
}

data "opendirectory_compliance_status" "eng_device" {
  device_id = opendirectory_device.macbook_eng_01.id
}

# ── Outputs ──────────────────────────────────────────────────────────────────

output "macos_device_count" {
  description = "Number of active macOS devices"
  value       = length(data.opendirectory_devices.macos_fleet.devices)
}

output "compliance_score" {
  description = "Compliance score for the engineering device"
  value       = data.opendirectory_compliance_status.eng_device.score
}

output "compliance_status" {
  description = "Compliance status for the engineering device"
  value       = data.opendirectory_compliance_status.eng_device.status
}

output "security_policy_id" {
  description = "ID of the security baseline policy"
  value       = opendirectory_policy.security_baseline.id
}

output "wifi_cert_fingerprint" {
  description = "Fingerprint of the WiFi client certificate"
  value       = opendirectory_certificate.wifi_cert.fingerprint
}
