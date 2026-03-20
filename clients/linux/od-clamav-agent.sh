#!/bin/bash
# OpenDirectory ClamAV Antivirus Agent for Linux
# Installs, configures, and manages ClamAV with OpenDirectory MDM integration
# Communicates with the antivirus-protection server service on port 3905

set -euo pipefail

# ============================================================
# Constants and Configuration
# ============================================================

readonly AGENT_VERSION="1.0.0"
readonly OD_DIR="/opt/opendirectory"
readonly OD_DATA_DIR="/var/lib/opendirectory"
readonly QUARANTINE_DIR="$OD_DATA_DIR/quarantine"
readonly LOG_DIR="/var/log/opendirectory"
readonly LOG_FILE="$LOG_DIR/clamav.log"
readonly CONFIG_DIR="/etc/opendirectory/clamav"
readonly SERVICE_NAME="opendirectory-clamav"
readonly PID_FILE="/var/run/${SERVICE_NAME}.pid"
readonly STATE_FILE="$OD_DATA_DIR/clamav-state.json"

# Defaults (overridden by command-line args)
SERVER_URL="https://mdm.opendirectory.local:3905"
DEVICE_ID=""
API_KEY=""
SCAN_SCHEDULE="default"  # default, aggressive, light
ACTION="install"

# Scan schedule presets (minutes)
QUICK_INTERVAL_DEFAULT=60
FULL_INTERVAL_DEFAULT=10080
QUICK_INTERVAL_AGGRESSIVE=30
FULL_INTERVAL_AGGRESSIVE=1440
QUICK_INTERVAL_LIGHT=240
FULL_INTERVAL_LIGHT=10080

# Quick scan paths
QUICK_SCAN_PATHS="/home /tmp /var/tmp /root /dev/shm"
FULL_SCAN_PATHS="/"

# ============================================================
# Argument Parsing
# ============================================================

usage() {
    cat <<USAGE
OpenDirectory ClamAV Agent for Linux

Usage: $0 [OPTIONS]

Options:
    --server-url URL      OpenDirectory server URL (default: https://mdm.opendirectory.local:3905)
    --device-id ID        Device identifier (auto-detected if not provided)
    --api-key KEY         API key for server authentication
    --schedule SCHEDULE   Scan schedule: default, aggressive, light (default: default)
    --action ACTION       Action: install, uninstall, update, scan, status (default: install)
    --help                Show this help message

Examples:
    sudo $0 --server-url https://mdm.example.com:3905 --api-key mykey123
    sudo $0 --action scan
    sudo $0 --action status
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)  SERVER_URL="$2"; shift 2 ;;
        --device-id)   DEVICE_ID="$2"; shift 2 ;;
        --api-key)     API_KEY="$2"; shift 2 ;;
        --schedule)    SCAN_SCHEDULE="$2"; shift 2 ;;
        --action)      ACTION="$2"; shift 2 ;;
        --help)        usage ;;
        *)             echo "Unknown option: $1"; usage ;;
    esac
done

# ============================================================
# Logging Functions
# ============================================================

init_logging() {
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

log() {
    local level="${1:-INFO}"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# ============================================================
# Utility Functions
# ============================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
        DISTRO_NAME="${PRETTY_NAME:-$ID}"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
        DISTRO_VERSION=$(grep -oP '\d+\.\d+' /etc/redhat-release | head -1)
        DISTRO_NAME=$(cat /etc/redhat-release)
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
    log_info "Detected distribution: $DISTRO_NAME"
}

detect_device_id() {
    if [[ -n "$DEVICE_ID" ]]; then
        return
    fi

    # Try DMI product UUID
    if [[ -r /sys/class/dmi/id/product_uuid ]]; then
        DEVICE_ID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || true)
    fi

    # Try machine-id
    if [[ -z "$DEVICE_ID" ]] && [[ -r /etc/machine-id ]]; then
        DEVICE_ID=$(cat /etc/machine-id)
    fi

    # Fallback to generated UUID
    if [[ -z "$DEVICE_ID" ]]; then
        if [[ -f "$OD_DATA_DIR/device-id" ]]; then
            DEVICE_ID=$(cat "$OD_DATA_DIR/device-id")
        else
            DEVICE_ID=$(cat /proc/sys/kernel/random/uuid)
            mkdir -p "$OD_DATA_DIR"
            echo "$DEVICE_ID" > "$OD_DATA_DIR/device-id"
        fi
        log_warn "Generated fallback Device ID: $DEVICE_ID"
    fi

    log_info "Device ID: $DEVICE_ID"
}

get_schedule_intervals() {
    case "$SCAN_SCHEDULE" in
        aggressive)
            QUICK_INTERVAL=$QUICK_INTERVAL_AGGRESSIVE
            FULL_INTERVAL=$FULL_INTERVAL_AGGRESSIVE
            ;;
        light)
            QUICK_INTERVAL=$QUICK_INTERVAL_LIGHT
            FULL_INTERVAL=$FULL_INTERVAL_LIGHT
            ;;
        *)
            QUICK_INTERVAL=$QUICK_INTERVAL_DEFAULT
            FULL_INTERVAL=$FULL_INTERVAL_DEFAULT
            ;;
    esac
}

# ============================================================
# API Communication
# ============================================================

api_call() {
    local endpoint="$1"
    local body="$2"
    local uri="${SERVER_URL}/api/v1/antivirus${endpoint}"

    local response
    response=$(curl -s -w "\n%{http_code}" --max-time 30 \
        -X POST "$uri" \
        -H "Content-Type: application/json" \
        -H "X-Api-Key: $API_KEY" \
        -H "X-Device-Id: $DEVICE_ID" \
        -H "X-Agent-Version: $AGENT_VERSION" \
        -H "X-Platform: linux" \
        -d "$body" 2>/dev/null) || true

    local http_code
    http_code=$(echo "$response" | tail -1)
    local body_response
    body_response=$(echo "$response" | sed '$d')

    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        log_debug "API call successful: $endpoint (HTTP $http_code)"
        echo "$body_response"
        return 0
    else
        log_error "API call failed: $endpoint (HTTP $http_code)"
        return 1
    fi
}

send_heartbeat() {
    local clam_version="unknown"
    local sig_version="unknown"
    local clamd_running="false"
    local quarantine_count=0

    if command -v clamscan &>/dev/null; then
        clam_version=$(clamscan --version 2>/dev/null | head -1 || echo "unknown")
    fi

    if systemctl is-active --quiet clamav-daemon 2>/dev/null || \
       pgrep -x clamd &>/dev/null; then
        clamd_running="true"
    fi

    if [[ -d "$QUARANTINE_DIR" ]]; then
        quarantine_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    fi

    local last_quick_scan="null"
    local last_full_scan="null"
    if [[ -f "$STATE_FILE" ]]; then
        last_quick_scan=$(jq -r '.last_quick_scan // "null"' "$STATE_FILE" 2>/dev/null || echo "null")
        last_full_scan=$(jq -r '.last_full_scan // "null"' "$STATE_FILE" 2>/dev/null || echo "null")
    fi

    local hostname_val
    hostname_val=$(hostname -f 2>/dev/null || hostname)
    local kernel_ver
    kernel_ver=$(uname -r)

    local body
    body=$(cat <<HEARTBEAT_JSON
{
    "device_id": "$DEVICE_ID",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "status": $(if [[ "$clamd_running" == "true" ]]; then echo '"active"'; else echo '"degraded"'; fi),
    "clamav_version": "$clam_version",
    "engine_running": $clamd_running,
    "realtime_enabled": $clamd_running,
    "quarantine_count": $quarantine_count,
    "last_quick_scan": "$last_quick_scan",
    "last_full_scan": "$last_full_scan",
    "os_info": {
        "platform": "linux",
        "distribution": "$DISTRO",
        "version": "$DISTRO_VERSION",
        "hostname": "$hostname_val",
        "kernel": "$kernel_ver",
        "arch": "$(uname -m)"
    }
}
HEARTBEAT_JSON
)
    api_call "/heartbeat" "$body" >/dev/null 2>&1 && log_debug "Heartbeat sent" || log_warn "Heartbeat failed"
}

send_scan_report() {
    local scan_type="$1"
    local scan_path="$2"
    local files_scanned="$3"
    local threats_found="$4"
    local threats_json="$5"
    local duration="$6"
    local status="$7"

    local body
    body=$(cat <<SCAN_JSON
{
    "device_id": "$DEVICE_ID",
    "scan_type": "$scan_type",
    "scan_path": "$scan_path",
    "completed_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "duration_seconds": $duration,
    "files_scanned": $files_scanned,
    "threats_found": $threats_found,
    "threats": $threats_json,
    "status": "$status",
    "platform": "linux"
}
SCAN_JSON
)
    api_call "/scan-report" "$body" >/dev/null 2>&1 && \
        log_info "Scan report submitted: $scan_type ($threats_found threats)" || \
        log_warn "Failed to submit scan report"
}

send_threat_report() {
    local file_path="$1"
    local threat_name="$2"
    local action_taken="$3"
    local quarantine_path="$4"

    local body
    body=$(cat <<THREAT_JSON
{
    "device_id": "$DEVICE_ID",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "file_path": "$file_path",
    "threat_name": "$threat_name",
    "action_taken": "$action_taken",
    "quarantine_path": "$quarantine_path",
    "platform": "linux"
}
THREAT_JSON
)
    api_call "/threat-detected" "$body" >/dev/null 2>&1 || true
}

# ============================================================
# ClamAV Installation
# ============================================================

install_clamav_packages() {
    log_info "Installing ClamAV packages for $DISTRO..."

    case "$DISTRO" in
        ubuntu|debian|pop|linuxmint|elementary)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq clamav clamav-daemon clamav-freshclam clamav-base \
                clamdscan libclamunrar9 jq curl 2>/dev/null || \
            apt-get install -y -qq clamav clamav-daemon clamav-freshclam clamav-base \
                clamdscan jq curl
            # Install clamonacc if available (on-access scanning)
            apt-get install -y -qq clamav-clamonacc 2>/dev/null || true
            ;;
        fedora)
            dnf install -y clamav clamav-update clamd clamav-server clamav-server-systemd \
                clamav-filesystem jq curl
            ;;
        rhel|centos|rocky|almalinux|ol)
            # Enable EPEL for ClamAV
            if ! rpm -q epel-release &>/dev/null; then
                if command -v dnf &>/dev/null; then
                    dnf install -y epel-release
                else
                    yum install -y epel-release
                fi
            fi
            if command -v dnf &>/dev/null; then
                dnf install -y clamav clamav-update clamd clamav-server clamav-server-systemd \
                    clamav-filesystem jq curl
            else
                yum install -y clamav clamav-update clamd clamav-server clamav-server-systemd \
                    clamav-filesystem jq curl
            fi
            ;;
        opensuse*|sles|suse)
            zypper install -y clamav jq curl
            ;;
        arch|manjaro|endeavouros)
            pacman -S --noconfirm clamav jq curl
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_error "Please install ClamAV manually and re-run with --action install"
            exit 1
            ;;
    esac

    log_info "ClamAV packages installed"
}

# ============================================================
# ClamAV Configuration
# ============================================================

create_directories() {
    local dirs=(
        "$OD_DATA_DIR"
        "$QUARANTINE_DIR"
        "$LOG_DIR"
        "$CONFIG_DIR"
        "$CONFIG_DIR/signatures"
    )
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done

    # Set ownership
    local clamav_user="clamav"
    if ! id "$clamav_user" &>/dev/null; then
        clamav_user="clam"
        if ! id "$clamav_user" &>/dev/null; then
            useradd --system --no-create-home --shell /sbin/nologin clamav 2>/dev/null || true
            clamav_user="clamav"
        fi
    fi
    CLAMAV_USER="$clamav_user"

    chown -R "$CLAMAV_USER":"$CLAMAV_USER" "$CONFIG_DIR/signatures" 2>/dev/null || true
    chown -R root:root "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"
    chmod 750 "$LOG_DIR"

    log_info "Directories created"
}

write_clamd_conf() {
    log_info "Writing clamd.conf..."

    cat > "$CONFIG_DIR/clamd.conf" <<CLAMD_CONF
# OpenDirectory ClamAV Daemon Configuration
# Generated by od-clamav-agent.sh

# Logging
LogFile $LOG_DIR/clamd.log
LogFileMaxSize 50M
LogTime yes
LogRotate yes
LogVerbose no
LogSyslog yes
LogFacility LOG_LOCAL6

# Daemon settings
LocalSocket /var/run/clamd.scan/clamd.sock
LocalSocketGroup $CLAMAV_USER
LocalSocketMode 660
FixStaleSocket yes
TCPSocket 3310
TCPAddr 127.0.0.1
User $CLAMAV_USER
MaxConnectionQueueLength 30
MaxThreads 12
ReadTimeout 180
CommandReadTimeout 30
SendBufTimeout 200
IdleTimeout 60

# Database
DatabaseDirectory $CONFIG_DIR/signatures

# Scanning limits
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 17
MaxFiles 10000
MaxEmbeddedPE 40M
MaxHTMLNormalize 40M
MaxHTMLNoTags 8M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
MaxPartitions 50
MaxIconsPE 200

# Scanning options
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanXMLDOCS yes
ScanHWP3 yes
ScanMail yes
ScanArchive yes
AlertBrokenExecutables yes
AlertEncrypted yes
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes

# Heuristics
HeuristicAlerts yes
HeuristicScanPrecedence yes

# Bytecode engine
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 60000

# On-access scanning (via clamonacc)
OnAccessIncludePath /home
OnAccessIncludePath /tmp
OnAccessIncludePath /var/tmp
OnAccessIncludePath /root
OnAccessExcludePath $QUARANTINE_DIR
OnAccessExcludePath /proc
OnAccessExcludePath /sys
OnAccessExcludePath /dev
OnAccessExcludePath /run
OnAccessMaxFileSize 50M
OnAccessPrevention yes
OnAccessExtraScanning yes
OnAccessExcludeUname $CLAMAV_USER

# Self-check interval
SelfCheck 3600

# Exclude our own directories
ExcludePath ^$QUARANTINE_DIR
ExcludePath ^$LOG_DIR
ExcludePath ^/proc
ExcludePath ^/sys
CLAMD_CONF

    # Create socket directory
    mkdir -p /var/run/clamd.scan
    chown "$CLAMAV_USER":"$CLAMAV_USER" /var/run/clamd.scan

    log_info "clamd.conf written to $CONFIG_DIR/clamd.conf"
}

write_freshclam_conf() {
    log_info "Writing freshclam.conf..."

    cat > "$CONFIG_DIR/freshclam.conf" <<FRESHCLAM_CONF
# OpenDirectory FreshClam Configuration
# Generated by od-clamav-agent.sh

# Database settings
DatabaseDirectory $CONFIG_DIR/signatures
DatabaseOwner $CLAMAV_USER

# Logging
UpdateLogFile $LOG_DIR/freshclam.log
LogFileMaxSize 10M
LogTime yes
LogRotate yes
LogVerbose no
LogSyslog yes
LogFacility LOG_LOCAL6

# Mirror settings
DatabaseMirror database.clamav.net
ScriptedUpdates yes
CompressLocalDatabase no

# Check interval (checks per day, max 50)
Checks 24

# Connection settings
ConnectTimeout 30
ReceiveTimeout 60
DNSDatabaseInfo current.cvd.clamav.net
MaxAttempts 3

# Notify clamd on update
NotifyClamd $CONFIG_DIR/clamd.conf

# Safebrowsing
SafeBrowsing yes

# HTTP settings
HTTPUserAgent OpenDirectory-ClamAV/1.0 (Linux)
FRESHCLAM_CONF

    chown "$CLAMAV_USER":"$CLAMAV_USER" "$CONFIG_DIR/freshclam.conf"
    chmod 640 "$CONFIG_DIR/freshclam.conf"

    log_info "freshclam.conf written to $CONFIG_DIR/freshclam.conf"
}

update_signatures() {
    log_info "Updating ClamAV signatures..."

    # Stop system freshclam if running to avoid lock conflicts
    systemctl stop clamav-freshclam 2>/dev/null || true

    local output
    if output=$(freshclam --config-file="$CONFIG_DIR/freshclam.conf" \
                --datadir="$CONFIG_DIR/signatures" 2>&1); then
        log_info "Signature update completed successfully"

        # Report to server
        api_call "/signature-update" "$(cat <<SIG_JSON
{
    "device_id": "$DEVICE_ID",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "status": "success",
    "platform": "linux"
}
SIG_JSON
)" >/dev/null 2>&1 || true

        # Update state
        update_state "last_signature_update" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        return 0
    else
        local exit_code=$?
        # Exit code 1 from freshclam means database is already up to date
        if [[ $exit_code -eq 1 ]]; then
            log_info "Signatures already up to date"
            return 0
        fi
        log_warn "Signature update exited with code $exit_code"
        log_debug "freshclam output: $output"
        return 1
    fi
}

# ============================================================
# State Management
# ============================================================

init_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" <<STATE_JSON
{
    "installed_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "server_url": "$SERVER_URL",
    "device_id": "$DEVICE_ID",
    "last_quick_scan": null,
    "last_full_scan": null,
    "last_signature_update": null
}
STATE_JSON
    fi
}

update_state() {
    local key="$1"
    local value="$2"
    if [[ -f "$STATE_FILE" ]] && command -v jq &>/dev/null; then
        local tmp
        tmp=$(mktemp)
        jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
    fi
}

# ============================================================
# Scanning Functions
# ============================================================

run_scan() {
    local scan_type="$1"
    local scan_paths

    if [[ "$scan_type" == "quick" ]]; then
        scan_paths="$QUICK_SCAN_PATHS"
    else
        scan_paths="$FULL_SCAN_PATHS"
    fi

    log_info "Starting $scan_type scan..."
    local start_time
    start_time=$(date +%s)

    local total_files=0
    local total_threats=0
    local threats_json="[]"
    local scan_log="$LOG_DIR/scan-$(date '+%Y%m%d%H%M%S').log"

    for scan_path in $scan_paths; do
        if [[ ! -e "$scan_path" ]]; then
            log_warn "Scan path does not exist: $scan_path"
            continue
        fi

        log_info "Scanning: $scan_path"

        local output
        output=$(clamscan \
            --database="$CONFIG_DIR/signatures" \
            --log="$scan_log" \
            --recursive \
            --infected \
            --move="$QUARANTINE_DIR" \
            --max-filesize=100M \
            --max-scansize=400M \
            --max-recursion=17 \
            --max-files=50000 \
            --exclude-dir="^$QUARANTINE_DIR" \
            --exclude-dir="^/proc" \
            --exclude-dir="^/sys" \
            --exclude-dir="^/dev" \
            --exclude-dir="^/run" \
            "$scan_path" 2>&1) || true

        # Parse results
        local files
        files=$(echo "$output" | grep -oP 'Scanned files:\s*\K\d+' || echo "0")
        local infected
        infected=$(echo "$output" | grep -oP 'Infected files:\s*\K\d+' || echo "0")

        total_files=$((total_files + files))
        total_threats=$((total_threats + infected))

        # Parse individual threats
        while IFS= read -r line; do
            if [[ "$line" =~ ^(.+):\ (.+)\ FOUND$ ]]; then
                local threat_file="${BASH_REMATCH[1]}"
                local threat_name="${BASH_REMATCH[2]}"
                local quarantine_file="$QUARANTINE_DIR/$(basename "$threat_file")"

                log_warn "THREAT DETECTED: $threat_name in $threat_file - quarantined"

                # Add to threats JSON
                if command -v jq &>/dev/null; then
                    threats_json=$(echo "$threats_json" | jq --arg fp "$threat_file" --arg tn "$threat_name" \
                        --arg qp "$quarantine_file" \
                        '. + [{"file_path": $fp, "threat_name": $tn, "action": "quarantined", "quarantine_path": $qp}]')
                fi

                send_threat_report "$threat_file" "$threat_name" "quarantined" "$quarantine_file"
            fi
        done <<< "$output"
    done

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Update state
    if [[ "$scan_type" == "quick" ]]; then
        update_state "last_quick_scan" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    else
        update_state "last_full_scan" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    fi

    # Report to server
    send_scan_report "$scan_type" "$scan_paths" "$total_files" "$total_threats" \
        "$threats_json" "$duration" "completed"

    log_info "$scan_type scan complete: $total_files files, $total_threats threats, ${duration}s elapsed"
}

# ============================================================
# Systemd Service and Timer Setup
# ============================================================

install_systemd_units() {
    log_info "Installing systemd service and timers..."

    get_schedule_intervals

    # ---- Main agent service (heartbeat + command polling daemon) ----
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<SYSTEMD_SERVICE
[Unit]
Description=OpenDirectory ClamAV Antivirus Agent
Documentation=https://docs.opendirectory.local/agents/clamav
After=network-online.target clamav-daemon.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash $OD_DIR/od-clamav-daemon.sh
Restart=always
RestartSec=30
StandardOutput=append:$LOG_DIR/clamav-daemon.log
StandardError=append:$LOG_DIR/clamav-daemon.log
EnvironmentFile=-/etc/opendirectory/clamav/agent.env

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=$OD_DATA_DIR $LOG_DIR $QUARANTINE_DIR $CONFIG_DIR /var/run/clamd.scan
ProtectHome=read-only
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

    # ---- Write the daemon script ----
    cat > "$OD_DIR/od-clamav-daemon.sh" <<'DAEMON_SCRIPT'
#!/bin/bash
# OpenDirectory ClamAV Daemon - heartbeat and command polling loop

set -uo pipefail

DAEMON_SCRIPT

    # Append the configuration (not inside heredoc to allow variable expansion)
    cat >> "$OD_DIR/od-clamav-daemon.sh" <<DAEMON_CONFIG
CONFIG_DIR="$CONFIG_DIR"
LOG_DIR="$LOG_DIR"
LOG_FILE="$LOG_FILE"
QUARANTINE_DIR="$QUARANTINE_DIR"
STATE_FILE="$STATE_FILE"
SERVER_URL="$SERVER_URL"
DEVICE_ID="$DEVICE_ID"
API_KEY="$API_KEY"
AGENT_VERSION="$AGENT_VERSION"
OD_DIR="$OD_DIR"
QUICK_SCAN_PATHS="$QUICK_SCAN_PATHS"
FULL_SCAN_PATHS="$FULL_SCAN_PATHS"
DISTRO="${DISTRO:-unknown}"
DISTRO_VERSION="${DISTRO_VERSION:-unknown}"
CLAMAV_USER="${CLAMAV_USER:-clamav}"

DAEMON_CONFIG

    cat >> "$OD_DIR/od-clamav-daemon.sh" <<'DAEMON_BODY'
log_daemon() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DAEMON] [$level] $*" >> "$LOG_FILE"
}

api_call() {
    local endpoint="$1"
    local body="$2"
    curl -s --max-time 30 \
        -X POST "${SERVER_URL}/api/v1/antivirus${endpoint}" \
        -H "Content-Type: application/json" \
        -H "X-Api-Key: $API_KEY" \
        -H "X-Device-Id: $DEVICE_ID" \
        -H "X-Agent-Version: $AGENT_VERSION" \
        -H "X-Platform: linux" \
        -d "$body" 2>/dev/null || true
}

send_heartbeat() {
    local clamd_running="false"
    if pgrep -x clamd &>/dev/null; then clamd_running="true"; fi

    local quarantine_count=0
    if [[ -d "$QUARANTINE_DIR" ]]; then
        quarantine_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    fi

    local last_quick="null" last_full="null"
    if [[ -f "$STATE_FILE" ]] && command -v jq &>/dev/null; then
        last_quick=$(jq -r '.last_quick_scan // "null"' "$STATE_FILE" 2>/dev/null || echo "null")
        last_full=$(jq -r '.last_full_scan // "null"' "$STATE_FILE" 2>/dev/null || echo "null")
    fi

    api_call "/heartbeat" "{
        \"device_id\": \"$DEVICE_ID\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"status\": $(if [[ "$clamd_running" == "true" ]]; then echo '\"active\"'; else echo '\"degraded\"'; fi),
        \"engine_running\": $clamd_running,
        \"realtime_enabled\": $clamd_running,
        \"quarantine_count\": $quarantine_count,
        \"last_quick_scan\": \"$last_quick\",
        \"last_full_scan\": \"$last_full\",
        \"platform\": \"linux\",
        \"os_info\": {
            \"distribution\": \"$DISTRO\",
            \"version\": \"$DISTRO_VERSION\",
            \"hostname\": \"$(hostname)\",
            \"kernel\": \"$(uname -r)\",
            \"arch\": \"$(uname -m)\"
        }
    }" >/dev/null 2>&1
    log_daemon "DEBUG" "Heartbeat sent"
}

check_server_commands() {
    local response
    response=$(api_call "/pending-commands" "{\"device_id\": \"$DEVICE_ID\"}" 2>/dev/null) || return

    if [[ -z "$response" ]] || [[ "$response" == "null" ]]; then return; fi

    if command -v jq &>/dev/null; then
        local cmd_count
        cmd_count=$(echo "$response" | jq -r '.commands | length' 2>/dev/null || echo "0")
        if [[ "$cmd_count" -gt 0 ]]; then
            echo "$response" | jq -r '.commands[].action' 2>/dev/null | while read -r action; do
                log_daemon "INFO" "Server command received: $action"
                case "$action" in
                    quick_scan)
                        bash "$OD_DIR/od-clamav-agent.sh" --server-url "$SERVER_URL" --device-id "$DEVICE_ID" --api-key "$API_KEY" --action scan 2>&1 >> "$LOG_FILE" &
                        ;;
                    full_scan)
                        bash "$OD_DIR/od-clamav-agent.sh" --server-url "$SERVER_URL" --device-id "$DEVICE_ID" --api-key "$API_KEY" --action scan 2>&1 >> "$LOG_FILE" &
                        ;;
                    update_sigs)
                        freshclam --config-file="$CONFIG_DIR/freshclam.conf" --datadir="$CONFIG_DIR/signatures" 2>&1 >> "$LOG_FILE" || true
                        ;;
                    *)
                        log_daemon "WARN" "Unknown command: $action"
                        ;;
                esac
            done
        fi
    fi
}

# ---- Main loop ----
log_daemon "INFO" "OpenDirectory ClamAV daemon starting"
log_daemon "INFO" "Server: $SERVER_URL | Device: $DEVICE_ID"

HEARTBEAT_COUNTER=0

# Ensure clamd is running with our config
if ! pgrep -x clamd &>/dev/null; then
    log_daemon "INFO" "Starting clamd..."
    clamd --config-file="$CONFIG_DIR/clamd.conf" 2>/dev/null || log_daemon "WARN" "Failed to start clamd"
fi

# Start clamonacc for on-access scanning if available
if command -v clamonacc &>/dev/null; then
    if ! pgrep -x clamonacc &>/dev/null; then
        log_daemon "INFO" "Starting clamonacc (on-access scanning)..."
        clamonacc --config-file="$CONFIG_DIR/clamd.conf" --log="$LOG_DIR/clamonacc.log" --move="$QUARANTINE_DIR" 2>/dev/null &
        log_daemon "INFO" "clamonacc started"
    fi
fi

# Initial heartbeat
send_heartbeat

while true; do
    sleep 30
    HEARTBEAT_COUNTER=$((HEARTBEAT_COUNTER + 1))

    # Heartbeat every 5 minutes (10 x 30s)
    if [[ $((HEARTBEAT_COUNTER % 10)) -eq 0 ]]; then
        send_heartbeat
    fi

    # Check for server commands every 60 seconds (2 x 30s)
    if [[ $((HEARTBEAT_COUNTER % 2)) -eq 0 ]]; then
        check_server_commands
    fi

    # Restart clamd if it died
    if ! pgrep -x clamd &>/dev/null; then
        log_daemon "WARN" "clamd not running, restarting..."
        clamd --config-file="$CONFIG_DIR/clamd.conf" 2>/dev/null || log_daemon "ERROR" "Failed to restart clamd"
    fi
done
DAEMON_BODY

    chmod +x "$OD_DIR/od-clamav-daemon.sh"

    # ---- Quick scan timer ----
    cat > /etc/systemd/system/${SERVICE_NAME}-quickscan.service <<QUICK_SVC
[Unit]
Description=OpenDirectory ClamAV Quick Scan
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $OD_DIR/od-clamav-agent.sh --server-url $SERVER_URL --device-id $DEVICE_ID --api-key $API_KEY --action scan
Nice=19
IOSchedulingClass=idle
QUICK_SVC

    cat > /etc/systemd/system/${SERVICE_NAME}-quickscan.timer <<QUICK_TIMER
[Unit]
Description=OpenDirectory ClamAV Quick Scan Timer
Requires=${SERVICE_NAME}-quickscan.service

[Timer]
OnCalendar=*:0/${QUICK_INTERVAL}
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
QUICK_TIMER

    # ---- Full scan timer ----
    cat > /etc/systemd/system/${SERVICE_NAME}-fullscan.service <<FULL_SVC
[Unit]
Description=OpenDirectory ClamAV Full Scan
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $OD_DIR/od-clamav-agent.sh --server-url $SERVER_URL --device-id $DEVICE_ID --api-key $API_KEY --schedule $SCAN_SCHEDULE --action scan
Nice=19
IOSchedulingClass=idle
TimeoutStartSec=86400
FULL_SVC

    # Full scan: weekly on Sunday at 02:00 for default, daily at 02:00 for aggressive
    local full_calendar="Sun *-*-* 02:00:00"
    if [[ "$SCAN_SCHEDULE" == "aggressive" ]]; then
        full_calendar="*-*-* 02:00:00"
    fi

    cat > /etc/systemd/system/${SERVICE_NAME}-fullscan.timer <<FULL_TIMER
[Unit]
Description=OpenDirectory ClamAV Full Scan Timer
Requires=${SERVICE_NAME}-fullscan.service

[Timer]
OnCalendar=$full_calendar
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
FULL_TIMER

    # ---- Signature update timer ----
    cat > /etc/systemd/system/${SERVICE_NAME}-freshclam.service <<FRESH_SVC
[Unit]
Description=OpenDirectory ClamAV Signature Update
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/freshclam --config-file=$CONFIG_DIR/freshclam.conf --datadir=$CONFIG_DIR/signatures
User=$CLAMAV_USER
FRESH_SVC

    cat > /etc/systemd/system/${SERVICE_NAME}-freshclam.timer <<FRESH_TIMER
[Unit]
Description=OpenDirectory ClamAV Signature Update Timer
Requires=${SERVICE_NAME}-freshclam.service

[Timer]
OnCalendar=*:0/60
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
FRESH_TIMER

    # ---- Enable and start everything ----
    systemctl daemon-reload

    # Stop system ClamAV services to avoid conflicts
    systemctl stop clamav-daemon 2>/dev/null || true
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl disable clamav-daemon 2>/dev/null || true
    systemctl disable clamav-freshclam 2>/dev/null || true

    systemctl enable "$SERVICE_NAME"
    systemctl enable "${SERVICE_NAME}-quickscan.timer"
    systemctl enable "${SERVICE_NAME}-fullscan.timer"
    systemctl enable "${SERVICE_NAME}-freshclam.timer"

    systemctl start "$SERVICE_NAME"
    systemctl start "${SERVICE_NAME}-quickscan.timer"
    systemctl start "${SERVICE_NAME}-fullscan.timer"
    systemctl start "${SERVICE_NAME}-freshclam.timer"

    log_info "Systemd services and timers installed and started"
}

# ============================================================
# Security Profile Configuration (AppArmor / SELinux)
# ============================================================

configure_security_profiles() {
    log_info "Configuring security profiles..."

    # ---- AppArmor ----
    if command -v apparmor_status &>/dev/null && apparmor_status &>/dev/null; then
        log_info "Configuring AppArmor profile for ClamAV..."

        cat > /etc/apparmor.d/usr.sbin.clamd.opendirectory <<'APPARMOR_PROFILE'
#include <tunables/global>

profile clamd_opendirectory /usr/sbin/clamd flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # ClamAV binary and libraries
  /usr/sbin/clamd                   mr,
  /usr/bin/clamscan                 mr,
  /usr/bin/freshclam                mr,
  /usr/bin/clamdscan                mr,
  /usr/sbin/clamonacc               mr,
  /usr/lib/x86_64-linux-gnu/**     mr,

  # Configuration
  /etc/opendirectory/clamav/**      r,

  # Signatures database
  /etc/opendirectory/clamav/signatures/** rw,

  # Quarantine
  /var/lib/opendirectory/quarantine/** rw,

  # Logs
  /var/log/opendirectory/**          rw,

  # Socket
  /var/run/clamd.scan/               rw,
  /var/run/clamd.scan/clamd.sock     rw,

  # Scanning - need read access to all files
  /** r,

  # Temporary files
  /tmp/**                           rw,

  # System information
  /proc/meminfo                     r,
  /proc/cpuinfo                     r,
  /sys/devices/system/cpu/**        r,

  # Network for freshclam updates
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Deny write to sensitive paths
  deny /etc/shadow                  w,
  deny /etc/passwd                  w,
  deny /boot/**                     w,
}
APPARMOR_PROFILE

        apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd.opendirectory 2>/dev/null || \
            log_warn "Failed to load AppArmor profile (non-fatal)"

        log_info "AppArmor profile installed"
    fi

    # ---- SELinux ----
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
        log_info "Configuring SELinux policy for ClamAV..."

        # Create a custom SELinux policy module
        local selinux_dir
        selinux_dir=$(mktemp -d)

        cat > "$selinux_dir/opendirectory_clamav.te" <<'SELINUX_POLICY'
module opendirectory_clamav 1.0;

require {
    type clamd_t;
    type clamd_exec_t;
    type user_home_t;
    type tmp_t;
    type var_lib_t;
    type var_log_t;
    type var_run_t;
    type fs_t;
    type http_port_t;
    class file { read open getattr write create unlink rename };
    class dir { read open getattr search write add_name remove_name };
    class sock_file { read write create unlink getattr };
    class tcp_socket { name_connect };
    class unix_stream_socket connectto;
}

# Allow clamd to read all files for scanning
allow clamd_t user_home_t:file { read open getattr };
allow clamd_t user_home_t:dir { read open getattr search };
allow clamd_t tmp_t:file { read open getattr write create unlink rename };
allow clamd_t tmp_t:dir { read open getattr search write add_name remove_name };

# Allow quarantine operations
allow clamd_t var_lib_t:file { read open getattr write create unlink rename };
allow clamd_t var_lib_t:dir { read open getattr search write add_name remove_name };

# Allow logging
allow clamd_t var_log_t:file { read open getattr write create };
allow clamd_t var_log_t:dir { read open getattr search write add_name };

# Allow socket
allow clamd_t var_run_t:sock_file { read write create unlink getattr };
allow clamd_t var_run_t:dir { read open getattr search write add_name remove_name };

# Allow network for signature updates
allow clamd_t http_port_t:tcp_socket name_connect;
SELINUX_POLICY

        if command -v checkmodule &>/dev/null && command -v semodule_package &>/dev/null; then
            checkmodule -M -m -o "$selinux_dir/opendirectory_clamav.mod" \
                "$selinux_dir/opendirectory_clamav.te" 2>/dev/null && \
            semodule_package -o "$selinux_dir/opendirectory_clamav.pp" \
                -m "$selinux_dir/opendirectory_clamav.mod" 2>/dev/null && \
            semodule -i "$selinux_dir/opendirectory_clamav.pp" 2>/dev/null && \
            log_info "SELinux policy module installed" || \
            log_warn "Failed to install SELinux policy module (non-fatal)"
        else
            log_warn "SELinux policy build tools not available, skipping"
        fi

        # Set file contexts
        if command -v semanage &>/dev/null; then
            semanage fcontext -a -t clamd_var_lib_t "$QUARANTINE_DIR(/.*)?" 2>/dev/null || true
            semanage fcontext -a -t clamd_var_log_t "$LOG_DIR(/.*)?" 2>/dev/null || true
            semanage fcontext -a -t clamd_etc_t "$CONFIG_DIR(/.*)?" 2>/dev/null || true
            restorecon -Rv "$QUARANTINE_DIR" "$LOG_DIR" "$CONFIG_DIR" 2>/dev/null || true
            log_info "SELinux file contexts set"
        fi

        rm -rf "$selinux_dir"
    fi

    log_info "Security profile configuration complete"
}

# ============================================================
# Environment File
# ============================================================

write_env_file() {
    cat > "$CONFIG_DIR/agent.env" <<ENV_FILE
# OpenDirectory ClamAV Agent Environment
# Generated by od-clamav-agent.sh

OD_SERVER_URL=$SERVER_URL
OD_DEVICE_ID=$DEVICE_ID
OD_API_KEY=$API_KEY
OD_SCAN_SCHEDULE=$SCAN_SCHEDULE
ENV_FILE
    chmod 600 "$CONFIG_DIR/agent.env"
    log_info "Environment file written"
}

# ============================================================
# Uninstall
# ============================================================

do_uninstall() {
    log_info "Uninstalling OpenDirectory ClamAV Agent..."

    # Stop and disable services
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}-quickscan.timer" 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}-fullscan.timer" 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}-freshclam.timer" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}-quickscan.timer" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}-fullscan.timer" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}-freshclam.timer" 2>/dev/null || true

    # Remove systemd units
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    rm -f /etc/systemd/system/${SERVICE_NAME}-quickscan.service
    rm -f /etc/systemd/system/${SERVICE_NAME}-quickscan.timer
    rm -f /etc/systemd/system/${SERVICE_NAME}-fullscan.service
    rm -f /etc/systemd/system/${SERVICE_NAME}-fullscan.timer
    rm -f /etc/systemd/system/${SERVICE_NAME}-freshclam.service
    rm -f /etc/systemd/system/${SERVICE_NAME}-freshclam.timer
    systemctl daemon-reload

    # Stop clamd/clamonacc
    pkill -x clamonacc 2>/dev/null || true
    pkill -x clamd 2>/dev/null || true

    # Remove daemon script
    rm -f "$OD_DIR/od-clamav-daemon.sh"

    # Remove AppArmor profile
    rm -f /etc/apparmor.d/usr.sbin.clamd.opendirectory
    apparmor_parser -R /etc/apparmor.d/usr.sbin.clamd.opendirectory 2>/dev/null || true

    # Remove SELinux module
    semodule -r opendirectory_clamav 2>/dev/null || true

    # Deregister from server
    api_call "/deregister" "{
        \"device_id\": \"$DEVICE_ID\",
        \"platform\": \"linux\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"
    }" >/dev/null 2>&1 || true

    log_info "OpenDirectory ClamAV Agent uninstalled"
    log_info "ClamAV packages remain installed. Quarantined files at: $QUARANTINE_DIR"
    log_info "Configuration at: $CONFIG_DIR"
}

# ============================================================
# Status Display
# ============================================================

show_status() {
    echo ""
    echo "OpenDirectory ClamAV Agent Status"
    echo "=================================="
    echo ""

    # ClamAV installation
    if command -v clamscan &>/dev/null; then
        local version
        version=$(clamscan --version 2>/dev/null | head -1)
        echo "ClamAV Installed:     Yes"
        echo "ClamAV Version:       $version"
    else
        echo "ClamAV Installed:     No"
    fi

    # Service status
    local svc_status
    svc_status=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")
    echo "Service Status:       $svc_status"

    # clamd
    if pgrep -x clamd &>/dev/null; then
        echo "clamd (Real-time):    Running"
    else
        echo "clamd (Real-time):    Stopped"
    fi

    # clamonacc
    if pgrep -x clamonacc &>/dev/null; then
        echo "clamonacc (On-access): Running"
    else
        echo "clamonacc (On-access): Stopped"
    fi

    # Timers
    echo ""
    echo "Timers:"
    systemctl list-timers "${SERVICE_NAME}*" --no-pager 2>/dev/null || echo "  (none)"

    # State
    if [[ -f "$STATE_FILE" ]] && command -v jq &>/dev/null; then
        echo ""
        local last_quick last_full last_sig
        last_quick=$(jq -r '.last_quick_scan // "Never"' "$STATE_FILE" 2>/dev/null)
        last_full=$(jq -r '.last_full_scan // "Never"' "$STATE_FILE" 2>/dev/null)
        last_sig=$(jq -r '.last_signature_update // "Never"' "$STATE_FILE" 2>/dev/null)
        echo "Last Quick Scan:      $last_quick"
        echo "Last Full Scan:       $last_full"
        echo "Last Sig Update:      $last_sig"
    fi

    # Quarantine
    local q_count=0
    if [[ -d "$QUARANTINE_DIR" ]]; then
        q_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    fi
    echo "Quarantined Items:    $q_count"

    echo ""
    echo "Server URL:           $SERVER_URL"
    echo "Device ID:            $DEVICE_ID"
    echo "Scan Schedule:        $SCAN_SCHEDULE"
    echo "Config Dir:           $CONFIG_DIR"
    echo "Log File:             $LOG_FILE"
    echo "Quarantine Dir:       $QUARANTINE_DIR"
    echo ""
}

# ============================================================
# Main Installation
# ============================================================

do_install() {
    echo ""
    echo "OpenDirectory ClamAV Antivirus Agent - Linux"
    echo "============================================="
    echo ""

    create_directories
    install_clamav_packages
    write_clamd_conf
    write_freshclam_conf
    write_env_file
    init_state
    update_signatures
    configure_security_profiles
    install_systemd_units

    # Send initial heartbeat
    send_heartbeat

    # Register with server
    api_call "/register" "{
        \"device_id\": \"$DEVICE_ID\",
        \"platform\": \"linux\",
        \"hostname\": \"$(hostname -f 2>/dev/null || hostname)\",
        \"os_version\": \"$DISTRO_NAME\",
        \"kernel_version\": \"$(uname -r)\",
        \"agent_version\": \"$AGENT_VERSION\",
        \"config_dir\": \"$CONFIG_DIR\",
        \"scan_schedule\": \"$SCAN_SCHEDULE\"
    }" >/dev/null 2>&1 || log_warn "Server registration failed (non-fatal)"

    echo ""
    echo "Installation complete!"
    echo ""
    show_status
}

# ============================================================
# Main Entry Point
# ============================================================

check_root
init_logging
detect_distro
detect_device_id

log_info "OpenDirectory ClamAV Agent starting (Action: $ACTION)"
log_info "Server: $SERVER_URL | Device: $DEVICE_ID | Schedule: $SCAN_SCHEDULE"

case "$ACTION" in
    install)
        do_install
        ;;
    uninstall)
        do_uninstall
        ;;
    update)
        update_signatures
        ;;
    scan)
        run_scan "quick"
        ;;
    status)
        show_status
        ;;
    *)
        echo "Unknown action: $ACTION"
        usage
        ;;
esac

log_info "OpenDirectory ClamAV Agent action '$ACTION' completed"
