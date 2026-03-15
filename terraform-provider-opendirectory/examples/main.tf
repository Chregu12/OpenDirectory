# OpenDirectory Terraform Provider - Example Configuration

terraform {
  required_providers {
    opendirectory = {
      source = "Chregu12/opendirectory"
    }
  }
}

# Provider configuration
provider "opendirectory" {
  api_url = var.od_api_url
  api_key = var.od_api_key
  timeout = 30
}

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

# --- Security Baseline Policy ---
resource "opendirectory_policy" "security_baseline" {
  name        = "Security Baseline"
  description = "Enforces security baseline across all managed devices"
  type        = "security"
  priority    = 100
  enabled     = true

  rules = jsonencode({
    firewall_enabled    = true
    encryption_required = true
    min_password_length = 12
    screen_lock_timeout = 300
    auto_update_enabled = true
  })

  targets = ["all-managed-devices"]
}

# --- Corporate WiFi Profile ---
resource "opendirectory_wifi_profile" "corporate_wifi" {
  device_id     = "all"
  name          = "Corporate WiFi"
  ssid          = "Corp-WiFi"
  security_type = "WPA2-Enterprise"
  auto_join     = true
  hidden        = false
  eap_type      = "TLS"
}

# --- VPN Profile ---
resource "opendirectory_vpn_profile" "corporate_vpn" {
  device_id       = "all"
  name            = "Corporate VPN"
  vpn_type        = "IKEv2"
  server          = "vpn.example.com"
  remote_id       = "vpn.example.com"
  on_demand       = true
  on_demand_rules = "WiFiOnly"
}

# --- Update Policy ---
resource "opendirectory_update_policy" "standard_updates" {
  device_id          = "all"
  name               = "Standard Update Policy"
  auto_update        = true
  maintenance_window = "02:00-06:00"
  deferral_days      = 3
  force_restart      = false
  allow_user_defer   = true
  max_deferrals      = 5
  include_beta       = false
}

# --- Data Sources ---

# Get all macOS devices
data "opendirectory_devices" "macos_fleet" {
  platform = "macos"
}

# Get compliance status for a specific device
data "opendirectory_compliance_status" "check" {
  device_id = "device-001"
}

# --- Outputs ---
output "macos_device_count" {
  value = length(data.opendirectory_devices.macos_fleet.devices)
}

output "compliance_score" {
  value = data.opendirectory_compliance_status.check.score
}

output "security_policy_id" {
  value = opendirectory_policy.security_baseline.id
}
