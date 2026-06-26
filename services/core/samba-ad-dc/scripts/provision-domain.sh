#!/bin/bash
set -euo pipefail

# Samba AD DC Domain Provisioning Script
# Usage: provision-domain.sh <REALM> <DOMAIN> <ADMIN_PASSWORD> <DNS_BACKEND>
#        [DC_HOSTNAME] [DC_IP] [FUNCTION_LEVEL] [DNS_INTERFACE]
#        [DNS_FORWARDERS] [ENABLE_LDAPS] [ENABLE_RFC2307] [SERVER_ROLE]

REALM="${1:?Realm is required (e.g., CORP.LOCAL)}"
DOMAIN="${2:?Domain (NetBIOS) is required (e.g., CORP)}"
ADMIN_PASSWORD="${3:?Admin password is required}"
DNS_BACKEND="${4:-SAMBA_INTERNAL}"
DC_HOSTNAME="${5:-$(hostname -s)}"
DC_IP="${6:-}"
FUNCTION_LEVEL="${7:-2008_R2}"
DNS_INTERFACE="${8:-lo eth0}"
DNS_FORWARDERS="${9:-8.8.8.8 8.8.4.4}"
ENABLE_LDAPS="${10:-true}"
ENABLE_RFC2307="${11:-true}"
SERVER_ROLE="${12:-dc}"

LOG_FILE="/var/log/opendirectory/provision-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
error_exit() { log "ERROR: $1"; exit 1; }

# ── Validation ────────────────────────────────────────────────────────────────

validate_inputs() {
    if ! echo "$REALM" | grep -qE '^[A-Z][A-Z0-9.-]+\.[A-Z]{2,}$'; then
        error_exit "Invalid realm. Must be uppercase FQDN (e.g., CORP.LOCAL)"
    fi
    if ! echo "$DOMAIN" | grep -qE '^[A-Z][A-Z0-9]{0,14}$'; then
        error_exit "Invalid NetBIOS name. Max 15 uppercase alphanumeric chars."
    fi
    if [[ "$DNS_BACKEND" != "SAMBA_INTERNAL" && "$DNS_BACKEND" != "BIND9_DLZ" && "$DNS_BACKEND" != "BIND9_FLATFILE" ]]; then
        error_exit "DNS backend must be SAMBA_INTERNAL, BIND9_DLZ, or BIND9_FLATFILE"
    fi
    VALID_LEVELS="2000 2003 2008 2008_R2 2012 2012_R2 2016"
    if ! echo "$VALID_LEVELS" | grep -qw "$FUNCTION_LEVEL"; then
        error_exit "Function level must be one of: $VALID_LEVELS"
    fi
    if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
        error_exit "Admin password must be at least 8 characters"
    fi
}

# ── Pre-provisioning ──────────────────────────────────────────────────────────

backup_existing_config() {
    local backup_dir="/var/backups/samba/pre-provision-$(date +%Y%m%d-%H%M%S)"
    if [ -f /etc/samba/smb.conf ]; then
        log "Backing up existing Samba configuration to $backup_dir"
        mkdir -p "$backup_dir"
        cp /etc/samba/smb.conf "$backup_dir/" 2>/dev/null || true
        cp /etc/krb5.conf "$backup_dir/" 2>/dev/null || true
    fi
}

stop_conflicting_services() {
    log "Stopping conflicting Samba services..."
    systemctl stop smbd nmbd winbind 2>/dev/null || true
    systemctl disable smbd nmbd winbind 2>/dev/null || true
    [ -f /etc/samba/smb.conf ] && mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
}

# ── Core Provisioning ─────────────────────────────────────────────────────────

provision_domain() {
    log "=========================================="
    log "Provisioning Samba AD DC"
    log "  Realm:          $REALM"
    log "  NetBIOS:        $DOMAIN"
    log "  DC Hostname:    $DC_HOSTNAME"
    log "  DC IP:          ${DC_IP:-auto}"
    log "  Function Level: $FUNCTION_LEVEL"
    log "  DNS Backend:    $DNS_BACKEND"
    log "  DNS Interface:  $DNS_INTERFACE"
    log "  RFC2307:        $ENABLE_RFC2307"
    log "  LDAPS:          $ENABLE_LDAPS"
    log "=========================================="

    local PROVISION_ARGS=(
        --realm="$REALM"
        --domain="$DOMAIN"
        --server-role="$SERVER_ROLE"
        --dns-backend="$DNS_BACKEND"
        --adminpass="$ADMIN_PASSWORD"
        --function-level="$FUNCTION_LEVEL"
        --host-name="$DC_HOSTNAME"
        "--option=interfaces=lo $DNS_INTERFACE"
        "--option=bind interfaces only=yes"
    )

    [ -n "$DC_IP" ] && PROVISION_ARGS+=(--host-ip="$DC_IP")
    [ "$ENABLE_RFC2307" = "true" ] && PROVISION_ARGS+=(--use-rfc2307)

    samba-tool domain provision "${PROVISION_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"

    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        error_exit "samba-tool domain provision failed"
    fi
    log "Domain provisioned successfully"
}

# ── DNS Configuration ─────────────────────────────────────────────────────────

configure_dns() {
    log "Configuring DNS resolution (Samba internal → 127.0.0.1)..."
    cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search $(echo "$REALM" | tr '[:upper:]' '[:lower:]')
EOF
    log "DNS resolution configured"
}

configure_dns_forwarders() {
    if [ -z "$DNS_FORWARDERS" ]; then return; fi
    log "Configuring DNS forwarders: $DNS_FORWARDERS"
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
    for fwd in $DNS_FORWARDERS; do
        samba-tool dns forwarder add "$realm_lower" "$fwd" 2>/dev/null || \
            log "Warning: Could not add forwarder $fwd (non-fatal)"
    done
    log "DNS forwarders configured"
}

# ── Kerberos ──────────────────────────────────────────────────────────────────

configure_kerberos() {
    log "Configuring Kerberos..."
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')

    if [ -f /var/lib/samba/private/krb5.conf ]; then
        cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
        log "Kerberos config copied from Samba private"
    else
        cat > /etc/krb5.conf << KRB5
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false

[realms]
    $REALM = {
        kdc = $DC_HOSTNAME.$realm_lower
        admin_server = $DC_HOSTNAME.$realm_lower
        default_domain = $realm_lower
    }

[domain_realm]
    .$realm_lower = $REALM
    $realm_lower = $REALM
KRB5
        log "Kerberos config created manually"
    fi
}

# ── LDAPS Certificate ─────────────────────────────────────────────────────────

generate_ldaps_cert() {
    if [ "$ENABLE_LDAPS" != "true" ]; then
        log "LDAPS disabled — skipping certificate generation"
        return
    fi

    log "Generating self-signed LDAPS certificate..."
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
    local cert_dir="/etc/samba/tls"
    mkdir -p "$cert_dir"

    openssl req -newkey rsa:2048 -nodes \
        -keyout "$cert_dir/samba.key" \
        -x509 -days 3650 \
        -subj "/C=CH/O=OpenDirectory/CN=$DC_HOSTNAME.$realm_lower" \
        -addext "subjectAltName=DNS:$DC_HOSTNAME.$realm_lower,DNS:$realm_lower,IP:127.0.0.1${DC_IP:+,IP:$DC_IP}" \
        -out "$cert_dir/samba.crt" 2>/dev/null

    chmod 600 "$cert_dir/samba.key"

    # Append TLS config to smb.conf
    cat >> /etc/samba/smb.conf << TLS

    tls enabled  = yes
    tls keyfile  = $cert_dir/samba.key
    tls certfile = $cert_dir/samba.crt
    tls cafile   =
TLS
    log "LDAPS certificate generated ($cert_dir/samba.crt, valid 10 years)"
}

# ── SYSVOL ────────────────────────────────────────────────────────────────────

setup_sysvol() {
    log "Setting up SYSVOL..."
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
    local sysvol="/var/lib/samba/sysvol"

    chmod -R 755 "$sysvol" 2>/dev/null || true
    chown -R root:root "$sysvol" 2>/dev/null || true
    mkdir -p "$sysvol/$realm_lower/Policies" "$sysvol/$realm_lower/scripts" 2>/dev/null || true
    log "SYSVOL configured"
}

# ── Verification ──────────────────────────────────────────────────────────────

verify_provisioning() {
    log "Verifying provisioning..."
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')

    [ -f /etc/samba/smb.conf ]                         || error_exit "smb.conf missing"
    [ -d "/var/lib/samba/sysvol/$realm_lower" ]        || error_exit "SYSVOL missing"
    [ -f /var/lib/samba/private/sam.ldb ]              || error_exit "SAM database missing"
    log "Verification passed"
}

# ── Status file ───────────────────────────────────────────────────────────────

write_status() {
    local realm_lower
    realm_lower=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')

    # Build forwarder JSON array
    local fwd_json="[]"
    if [ -n "$DNS_FORWARDERS" ]; then
        fwd_json="["
        first=true
        for fwd in $DNS_FORWARDERS; do
            $first && first=false || fwd_json+=","
            fwd_json+="\"$fwd\""
        done
        fwd_json+="]"
    fi

    cat > /var/lib/samba/.opendirectory-status << STATUSEOF
{
    "provisioned":     true,
    "realm":           "$REALM",
    "domain":          "$DOMAIN",
    "dcHostname":      "$DC_HOSTNAME",
    "dcIp":            "${DC_IP:-}",
    "exposedFqdn":     "$DC_HOSTNAME.$realm_lower",
    "dnsBackend":      "$DNS_BACKEND",
    "dnsInterface":    "$DNS_INTERFACE",
    "dnsForwarders":   $fwd_json,
    "functionLevel":   "$FUNCTION_LEVEL",
    "ldapsEnabled":    $ENABLE_LDAPS,
    "rfc2307Enabled":  $ENABLE_RFC2307,
    "serverRole":      "$SERVER_ROLE",
    "provisionedAt":   "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname":        "$(hostname -f)",
    "sysvolPath":      "/var/lib/samba/sysvol/$realm_lower"
}
STATUSEOF
    log "Status file written to /var/lib/samba/.opendirectory-status"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    log "=========================================="
    log "OpenDirectory — Samba AD DC Provisioning"
    log "=========================================="

    validate_inputs
    backup_existing_config
    stop_conflicting_services
    provision_domain
    configure_kerberos
    configure_dns
    configure_dns_forwarders
    generate_ldaps_cert
    setup_sysvol
    verify_provisioning
    write_status

    log "=========================================="
    log "Provisioning complete — start Samba with:"
    log "  samba -F --no-process-group &"
    log "=========================================="
}

main
