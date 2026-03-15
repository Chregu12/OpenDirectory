#!/bin/bash
# OpenDirectory ClamAV Antivirus Agent for macOS
# Installs, configures, and manages ClamAV with OpenDirectory MDM integration
# Communicates with the antivirus-protection server service on port 3905

set -euo pipefail

# ============================================================
# Constants and Configuration
# ============================================================

readonly AGENT_VERSION="1.0.0"
readonly OD_DIR="/usr/local/opendirectory"
readonly OD_SUPPORT_DIR="/Library/Application Support/OpenDirectory"
readonly QUARANTINE_DIR="$OD_SUPPORT_DIR/Quarantine"
readonly LOG_DIR="/Library/Logs/OpenDirectory"
readonly LOG_FILE="$LOG_DIR/clamav.log"
readonly CONFIG_DIR="$OD_SUPPORT_DIR/ClamAV"
readonly SIGNATURES_DIR="$CONFIG_DIR/signatures"
readonly PLIST_LABEL="com.opendirectory.clamav"
readonly PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
readonly PLIST_FRESHCLAM_LABEL="com.opendirectory.clamav.freshclam"
readonly PLIST_FRESHCLAM_PATH="/Library/LaunchDaemons/${PLIST_FRESHCLAM_LABEL}.plist"
readonly PLIST_QUICKSCAN_LABEL="com.opendirectory.clamav.quickscan"
readonly PLIST_QUICKSCAN_PATH="/Library/LaunchDaemons/${PLIST_QUICKSCAN_LABEL}.plist"
readonly PLIST_FULLSCAN_LABEL="com.opendirectory.clamav.fullscan"
readonly PLIST_FULLSCAN_PATH="/Library/LaunchDaemons/${PLIST_FULLSCAN_LABEL}.plist"
readonly STATE_FILE="$OD_SUPPORT_DIR/clamav-state.json"

# Defaults
SERVER_URL="https://mdm.opendirectory.local:3905"
DEVICE_ID=""
API_KEY=""
SCAN_SCHEDULE="default"
ACTION="install"

# Scan schedule presets (seconds for launchd)
QUICK_INTERVAL_DEFAULT=3600      # 1 hour
QUICK_INTERVAL_AGGRESSIVE=1800   # 30 minutes
QUICK_INTERVAL_LIGHT=14400       # 4 hours
# Full scans use calendar intervals in launchd

QUICK_SCAN_PATHS="/Users /tmp /private/tmp /private/var/tmp"
FULL_SCAN_PATHS="/"

# ClamAV paths (set after installation detection)
CLAMSCAN_BIN=""
CLAMD_BIN=""
FRESHCLAM_BIN=""
CLAMCONF_BIN=""

# ============================================================
# Argument Parsing
# ============================================================

usage() {
    cat <<USAGE
OpenDirectory ClamAV Agent for macOS

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
# Logging
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
        log_error "This script must be run with sudo"
        exit 1
    fi
}

detect_device_id() {
    if [[ -n "$DEVICE_ID" ]]; then
        return
    fi

    DEVICE_ID=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Hardware UUID:/ {print $3}')

    if [[ -z "$DEVICE_ID" ]]; then
        DEVICE_ID=$(ioreg -d2 -c IOPlatformExpertDevice 2>/dev/null | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')
    fi

    if [[ -z "$DEVICE_ID" ]]; then
        if [[ -f "$OD_SUPPORT_DIR/device-id" ]]; then
            DEVICE_ID=$(cat "$OD_SUPPORT_DIR/device-id")
        else
            DEVICE_ID=$(uuidgen)
            mkdir -p "$OD_SUPPORT_DIR"
            echo "$DEVICE_ID" > "$OD_SUPPORT_DIR/device-id"
        fi
        log_warn "Generated fallback Device ID: $DEVICE_ID"
    fi

    log_info "Device ID: $DEVICE_ID"
}

detect_clamav_paths() {
    # Check Homebrew locations (Apple Silicon and Intel)
    local brew_prefixes=("/opt/homebrew" "/usr/local")
    for prefix in "${brew_prefixes[@]}"; do
        if [[ -x "$prefix/bin/clamscan" ]]; then
            CLAMSCAN_BIN="$prefix/bin/clamscan"
            CLAMD_BIN="$prefix/sbin/clamd"
            FRESHCLAM_BIN="$prefix/bin/freshclam"
            CLAMCONF_BIN="$prefix/bin/clamconf"
            log_info "ClamAV found at $prefix"
            return 0
        fi
    done

    # Check standard paths
    for bin in /usr/bin/clamscan /usr/local/bin/clamscan; do
        if [[ -x "$bin" ]]; then
            local dir
            dir=$(dirname "$bin")
            CLAMSCAN_BIN="$bin"
            CLAMD_BIN="$(dirname "$dir")/sbin/clamd"
            [[ ! -x "$CLAMD_BIN" ]] && CLAMD_BIN="$dir/clamd"
            FRESHCLAM_BIN="$dir/freshclam"
            CLAMCONF_BIN="$dir/clamconf"
            return 0
        fi
    done

    return 1
}

get_quick_interval() {
    case "$SCAN_SCHEDULE" in
        aggressive) echo "$QUICK_INTERVAL_AGGRESSIVE" ;;
        light)      echo "$QUICK_INTERVAL_LIGHT" ;;
        *)          echo "$QUICK_INTERVAL_DEFAULT" ;;
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
        -H "X-Platform: macos" \
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
    local clamd_running="false"
    local quarantine_count=0

    if [[ -n "$CLAMSCAN_BIN" ]] && [[ -x "$CLAMSCAN_BIN" ]]; then
        clam_version=$("$CLAMSCAN_BIN" --version 2>/dev/null | head -1 || echo "unknown")
    fi

    if pgrep -x clamd &>/dev/null; then
        clamd_running="true"
    fi

    if [[ -d "$QUARANTINE_DIR" ]]; then
        quarantine_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
    fi

    local last_quick="null" last_full="null"
    if [[ -f "$STATE_FILE" ]]; then
        last_quick=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_quick_scan','null'))" 2>/dev/null || echo "null")
        last_full=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_full_scan','null'))" 2>/dev/null || echo "null")
    fi

    local os_version
    os_version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    local hostname_val
    hostname_val=$(scutil --get ComputerName 2>/dev/null || hostname)
    local arch
    arch=$(uname -m)

    api_call "/heartbeat" "{
        \"device_id\": \"$DEVICE_ID\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"status\": $(if [[ "$clamd_running" == "true" ]]; then echo '\"active\"'; else echo '\"degraded\"'; fi),
        \"clamav_version\": \"$clam_version\",
        \"engine_running\": $clamd_running,
        \"realtime_enabled\": $clamd_running,
        \"quarantine_count\": $quarantine_count,
        \"last_quick_scan\": \"$last_quick\",
        \"last_full_scan\": \"$last_full\",
        \"os_info\": {
            \"platform\": \"macos\",
            \"version\": \"$os_version\",
            \"hostname\": \"$hostname_val\",
            \"arch\": \"$arch\"
        }
    }" >/dev/null 2>&1 && log_debug "Heartbeat sent" || log_warn "Heartbeat failed"
}

send_scan_report() {
    local scan_type="$1"
    local scan_path="$2"
    local files_scanned="$3"
    local threats_found="$4"
    local threats_json="$5"
    local duration="$6"
    local status="$7"

    api_call "/scan-report" "{
        \"device_id\": \"$DEVICE_ID\",
        \"scan_type\": \"$scan_type\",
        \"scan_path\": \"$scan_path\",
        \"completed_at\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"duration_seconds\": $duration,
        \"files_scanned\": $files_scanned,
        \"threats_found\": $threats_found,
        \"threats\": $threats_json,
        \"status\": \"$status\",
        \"platform\": \"macos\"
    }" >/dev/null 2>&1 && \
        log_info "Scan report submitted: $scan_type ($threats_found threats)" || \
        log_warn "Failed to submit scan report"
}

send_threat_report() {
    local file_path="$1"
    local threat_name="$2"
    local action_taken="$3"
    local quarantine_path="$4"

    api_call "/threat-detected" "{
        \"device_id\": \"$DEVICE_ID\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"file_path\": \"$file_path\",
        \"threat_name\": \"$threat_name\",
        \"action_taken\": \"$action_taken\",
        \"quarantine_path\": \"$quarantine_path\",
        \"platform\": \"macos\"
    }" >/dev/null 2>&1 || true
}

# ============================================================
# ClamAV Installation
# ============================================================

install_clamav() {
    log_info "Installing ClamAV..."

    if detect_clamav_paths; then
        log_info "ClamAV is already installed"
        return 0
    fi

    # Try Homebrew first
    if command -v brew &>/dev/null; then
        log_info "Installing ClamAV via Homebrew..."

        # Homebrew should not run as root; find the actual user
        local real_user
        real_user=$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$(whoami)}")

        if [[ "$real_user" != "root" ]]; then
            sudo -u "$real_user" brew install clamav 2>&1 | tee -a "$LOG_FILE"
        else
            # If we truly can't determine a non-root user, try direct brew
            brew install clamav 2>&1 | tee -a "$LOG_FILE" || true
        fi

        if detect_clamav_paths; then
            log_info "ClamAV installed via Homebrew"
            return 0
        fi
    fi

    # Try to find Homebrew in common locations
    for brew_path in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [[ -x "$brew_path" ]]; then
            log_info "Found Homebrew at $brew_path, installing ClamAV..."
            local real_user
            real_user=$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$(whoami)}")

            if [[ "$real_user" != "root" ]]; then
                sudo -u "$real_user" "$brew_path" install clamav 2>&1 | tee -a "$LOG_FILE"
            else
                "$brew_path" install clamav 2>&1 | tee -a "$LOG_FILE" || true
            fi

            if detect_clamav_paths; then
                log_info "ClamAV installed via Homebrew"
                return 0
            fi
        fi
    done

    # Fallback: Install Homebrew then ClamAV
    log_info "Homebrew not found, attempting to install Homebrew first..."
    local real_user
    real_user=$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$(whoami)}")

    if [[ "$real_user" != "root" ]]; then
        sudo -u "$real_user" /bin/bash -c \
            "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>&1 | tee -a "$LOG_FILE" || true

        # Retry detection of brew
        for brew_path in /opt/homebrew/bin/brew /usr/local/bin/brew; do
            if [[ -x "$brew_path" ]]; then
                sudo -u "$real_user" "$brew_path" install clamav 2>&1 | tee -a "$LOG_FILE"
                break
            fi
        done
    fi

    if detect_clamav_paths; then
        log_info "ClamAV installed successfully"
        return 0
    fi

    # Last resort: direct download from ClamAV
    log_info "Attempting direct ClamAV download..."
    local clamav_version="1.4.1"
    local pkg_url="https://www.clamav.net/downloads/production/clamav-${clamav_version}.mac.universal.pkg"
    local pkg_path="/tmp/clamav-install.pkg"

    if curl -fsSL -o "$pkg_path" "$pkg_url" 2>/dev/null; then
        installer -pkg "$pkg_path" -target / 2>&1 | tee -a "$LOG_FILE"
        rm -f "$pkg_path"

        if detect_clamav_paths; then
            log_info "ClamAV installed via direct download"
            return 0
        fi
    fi

    log_error "Failed to install ClamAV. Please install manually:"
    log_error "  brew install clamav"
    log_error "Then re-run this script."
    exit 1
}

# ============================================================
# ClamAV Configuration
# ============================================================

create_directories() {
    local dirs=(
        "$OD_SUPPORT_DIR"
        "$QUARANTINE_DIR"
        "$LOG_DIR"
        "$CONFIG_DIR"
        "$SIGNATURES_DIR"
        "$OD_DIR"
    )
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done

    chmod 700 "$QUARANTINE_DIR"
    chmod 750 "$LOG_DIR"

    log_info "Directories created"
}

write_clamd_conf() {
    log_info "Writing clamd.conf..."

    # Determine socket path
    local socket_dir="/var/run/clamav"
    mkdir -p "$socket_dir"

    cat > "$CONFIG_DIR/clamd.conf" <<CLAMD_CONF
# OpenDirectory ClamAV Daemon Configuration
# Generated by od-clamav-agent.sh for macOS

# Logging
LogFile $LOG_DIR/clamd.log
LogFileMaxSize 50M
LogTime yes
LogRotate yes
LogVerbose no

# Daemon settings
LocalSocket $socket_dir/clamd.sock
FixStaleSocket yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 30
MaxThreads 12
ReadTimeout 180
CommandReadTimeout 30
SendBufTimeout 200
IdleTimeout 60

# Database
DatabaseDirectory $SIGNATURES_DIR

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

# On-access scanning paths
OnAccessIncludePath /Users
OnAccessIncludePath /tmp
OnAccessIncludePath /private/tmp
OnAccessIncludePath /Applications
OnAccessExcludePath $QUARANTINE_DIR
OnAccessExcludePath /System
OnAccessExcludePath /Library/Caches
OnAccessMaxFileSize 50M
OnAccessPrevention yes
OnAccessExtraScanning yes

# Self-check interval
SelfCheck 3600

# Exclusions
ExcludePath ^$QUARANTINE_DIR
ExcludePath ^$LOG_DIR
ExcludePath ^/System
ExcludePath ^/Library/Caches
CLAMD_CONF

    log_info "clamd.conf written to $CONFIG_DIR/clamd.conf"
}

write_freshclam_conf() {
    log_info "Writing freshclam.conf..."

    cat > "$CONFIG_DIR/freshclam.conf" <<FRESHCLAM_CONF
# OpenDirectory FreshClam Configuration
# Generated by od-clamav-agent.sh for macOS

# Database settings
DatabaseDirectory $SIGNATURES_DIR

# Logging
UpdateLogFile $LOG_DIR/freshclam.log
LogFileMaxSize 10M
LogTime yes
LogRotate yes
LogVerbose no

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
HTTPUserAgent OpenDirectory-ClamAV/1.0 (macOS)
FRESHCLAM_CONF

    chmod 644 "$CONFIG_DIR/freshclam.conf"
    log_info "freshclam.conf written to $CONFIG_DIR/freshclam.conf"
}

update_signatures() {
    log_info "Updating ClamAV signatures..."

    if [[ -z "$FRESHCLAM_BIN" ]] || [[ ! -x "$FRESHCLAM_BIN" ]]; then
        detect_clamav_paths || true
        if [[ -z "$FRESHCLAM_BIN" ]]; then
            log_error "freshclam not found"
            return 1
        fi
    fi

    local output
    if output=$("$FRESHCLAM_BIN" --config-file="$CONFIG_DIR/freshclam.conf" \
                --datadir="$SIGNATURES_DIR" 2>&1); then
        log_info "Signature update completed successfully"

        api_call "/signature-update" "{
            \"device_id\": \"$DEVICE_ID\",
            \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
            \"status\": \"success\",
            \"platform\": \"macos\"
        }" >/dev/null 2>&1 || true

        update_state "last_signature_update" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 1 ]]; then
            log_info "Signatures already up to date"
            return 0
        fi
        log_warn "Signature update exited with code $exit_code"
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
    if [[ -f "$STATE_FILE" ]]; then
        /usr/bin/python3 -c "
import json, sys
with open('$STATE_FILE', 'r') as f:
    d = json.load(f)
d['$key'] = '$value'
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null || true
    fi
}

# ============================================================
# Scanning
# ============================================================

run_scan() {
    local scan_type="$1"
    local scan_paths

    if [[ "$scan_type" == "quick" ]]; then
        scan_paths="$QUICK_SCAN_PATHS"
    else
        scan_paths="$FULL_SCAN_PATHS"
    fi

    if [[ -z "$CLAMSCAN_BIN" ]] || [[ ! -x "$CLAMSCAN_BIN" ]]; then
        detect_clamav_paths || true
        if [[ -z "$CLAMSCAN_BIN" ]]; then
            log_error "clamscan not found"
            return 1
        fi
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
        output=$("$CLAMSCAN_BIN" \
            --database="$SIGNATURES_DIR" \
            --log="$scan_log" \
            --recursive \
            --infected \
            --move="$QUARANTINE_DIR" \
            --max-filesize=100M \
            --max-scansize=400M \
            --max-recursion=17 \
            --max-files=50000 \
            --exclude-dir="^$QUARANTINE_DIR" \
            --exclude-dir="^/System" \
            --exclude-dir="^/Library/Caches" \
            "$scan_path" 2>&1) || true

        # Parse results
        local files
        files=$(echo "$output" | grep -oE 'Scanned files:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' || echo "0")
        local infected
        infected=$(echo "$output" | grep -oE 'Infected files:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' || echo "0")

        total_files=$((total_files + files))
        total_threats=$((total_threats + infected))

        # Parse individual threats
        while IFS= read -r line; do
            if echo "$line" | grep -qE '^.+: .+ FOUND$'; then
                local threat_file
                threat_file=$(echo "$line" | sed -E 's/^(.+): .+ FOUND$/\1/')
                local threat_name
                threat_name=$(echo "$line" | sed -E 's/^.+: (.+) FOUND$/\1/')
                local quarantine_file="$QUARANTINE_DIR/$(basename "$threat_file")"

                log_warn "THREAT DETECTED: $threat_name in $threat_file - quarantined"

                # Add to threats JSON using python3 (available on macOS)
                threats_json=$(/usr/bin/python3 -c "
import json, sys
threats = json.loads('''$threats_json''')
threats.append({
    'file_path': '$threat_file',
    'threat_name': '$threat_name',
    'action': 'quarantined',
    'quarantine_path': '$quarantine_file'
})
print(json.dumps(threats))
" 2>/dev/null || echo "$threats_json")

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

    send_scan_report "$scan_type" "$scan_paths" "$total_files" "$total_threats" \
        "$threats_json" "$duration" "completed"

    log_info "$scan_type scan complete: $total_files files, $total_threats threats, ${duration}s elapsed"
}

# ============================================================
# macOS Permissions Handling
# ============================================================

handle_macos_permissions() {
    log_info "Checking macOS security permissions..."

    local os_major
    os_major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)

    if [[ "$os_major" -ge 10 ]]; then
        # Check for Full Disk Access
        # On macOS 10.14+, ClamAV needs Full Disk Access to scan all files

        # Create a helper script that users can run to check/prompt for permissions
        cat > "$OD_DIR/od-clamav-permissions.sh" <<'PERMS_SCRIPT'
#!/bin/bash
# OpenDirectory ClamAV - macOS Permissions Helper
# Run this script to check and request necessary permissions

echo ""
echo "OpenDirectory ClamAV - macOS Permissions"
echo "========================================="
echo ""
echo "ClamAV requires Full Disk Access to scan all files on your Mac."
echo ""
echo "To grant Full Disk Access:"
echo "  1. Open System Preferences (System Settings on macOS 13+)"
echo "  2. Go to Security & Privacy > Privacy > Full Disk Access"
echo "     (or Privacy & Security > Full Disk Access on macOS 13+)"
echo "  3. Click the lock to make changes"
echo "  4. Click '+' and add the following:"
PERMS_SCRIPT

        # Add the actual binary paths
        cat >> "$OD_DIR/od-clamav-permissions.sh" <<PERMS_PATHS
echo "     - $CLAMSCAN_BIN"
echo "     - $CLAMD_BIN"
echo "     - $FRESHCLAM_BIN"
echo "     - /bin/bash (for scan scripts)"
PERMS_PATHS

        cat >> "$OD_DIR/od-clamav-permissions.sh" <<'PERMS_END'
echo ""
echo "  5. Restart the OpenDirectory ClamAV service:"
echo "     sudo launchctl unload /Library/LaunchDaemons/com.opendirectory.clamav.plist"
echo "     sudo launchctl load /Library/LaunchDaemons/com.opendirectory.clamav.plist"
echo ""

# Attempt to check if Full Disk Access is granted
# by trying to read a protected file
if ls /Library/Application\ Support/com.apple.TCC/TCC.db &>/dev/null 2>&1; then
    echo "Full Disk Access: GRANTED"
else
    echo "Full Disk Access: NOT GRANTED (or unable to verify)"
    echo ""
    echo "Opening System Preferences..."
    if [[ "$(sw_vers -productVersion | cut -d. -f1)" -ge 13 ]]; then
        open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
    else
        open "/System/Library/PreferencePanes/Security.prefPane"
    fi
fi
PERMS_END

        chmod +x "$OD_DIR/od-clamav-permissions.sh"

        # Create TCC database entry request via MDM profile (if available)
        # This is the recommended way to grant Full Disk Access via MDM
        local tcc_profile="$OD_SUPPORT_DIR/clamav-tcc-profile.mobileconfig"
        cat > "$tcc_profile" <<TCC_PROFILE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadIdentifier</key>
            <string>com.opendirectory.clamav.tcc</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Services</key>
            <dict>
                <key>SystemPolicyAllFiles</key>
                <array>
                    <dict>
                        <key>Identifier</key>
                        <string>$CLAMSCAN_BIN</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Comment</key>
                        <string>OpenDirectory ClamAV Scanner</string>
                    </dict>
                    <dict>
                        <key>Identifier</key>
                        <string>$CLAMD_BIN</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Comment</key>
                        <string>OpenDirectory ClamAV Daemon</string>
                    </dict>
                </array>
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>OpenDirectory ClamAV Full Disk Access</string>
    <key>PayloadIdentifier</key>
    <string>com.opendirectory.clamav.tcc.profile</string>
    <key>PayloadOrganization</key>
    <string>OpenDirectory</string>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(uuidgen)</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
TCC_PROFILE

        log_info "TCC configuration profile created at $tcc_profile"
        log_info "Full Disk Access permissions helper created at $OD_DIR/od-clamav-permissions.sh"

        echo ""
        echo "IMPORTANT: ClamAV requires Full Disk Access on macOS."
        echo "  Run: sudo $OD_DIR/od-clamav-permissions.sh"
        echo "  Or deploy the MDM profile: $tcc_profile"
        echo ""
    fi
}

# ============================================================
# LaunchDaemon Setup
# ============================================================

install_launchd_services() {
    log_info "Installing launchd services..."

    local quick_interval
    quick_interval=$(get_quick_interval)

    # ---- Write the daemon script ----
    cat > "$OD_DIR/od-clamav-daemon.sh" <<DAEMON_HEADER
#!/bin/bash
# OpenDirectory ClamAV Daemon for macOS
# Heartbeat and command polling loop

set -uo pipefail

CONFIG_DIR="$CONFIG_DIR"
LOG_DIR="$LOG_DIR"
LOG_FILE="$LOG_FILE"
QUARANTINE_DIR="$QUARANTINE_DIR"
SIGNATURES_DIR="$SIGNATURES_DIR"
STATE_FILE="$STATE_FILE"
SERVER_URL="$SERVER_URL"
DEVICE_ID="$DEVICE_ID"
API_KEY="$API_KEY"
AGENT_VERSION="$AGENT_VERSION"
OD_DIR="$OD_DIR"
CLAMSCAN_BIN="$CLAMSCAN_BIN"
CLAMD_BIN="$CLAMD_BIN"
FRESHCLAM_BIN="$FRESHCLAM_BIN"
QUICK_SCAN_PATHS="$QUICK_SCAN_PATHS"
FULL_SCAN_PATHS="$FULL_SCAN_PATHS"

DAEMON_HEADER

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
        -H "X-Platform: macos" \
        -d "$body" 2>/dev/null || true
}

send_heartbeat() {
    local clamd_running="false"
    if pgrep -x clamd &>/dev/null; then clamd_running="true"; fi

    local quarantine_count=0
    if [[ -d "$QUARANTINE_DIR" ]]; then
        quarantine_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
    fi

    local last_quick="null" last_full="null"
    if [[ -f "$STATE_FILE" ]]; then
        last_quick=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_quick_scan','null'))" 2>/dev/null || echo "null")
        last_full=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_full_scan','null'))" 2>/dev/null || echo "null")
    fi

    local os_ver
    os_ver=$(sw_vers -productVersion 2>/dev/null || echo "unknown")

    api_call "/heartbeat" "{
        \"device_id\": \"$DEVICE_ID\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"status\": $(if [[ "$clamd_running" == "true" ]]; then echo '\"active\"'; else echo '\"degraded\"'; fi),
        \"engine_running\": $clamd_running,
        \"realtime_enabled\": $clamd_running,
        \"quarantine_count\": $quarantine_count,
        \"last_quick_scan\": \"$last_quick\",
        \"last_full_scan\": \"$last_full\",
        \"platform\": \"macos\",
        \"os_info\": {
            \"version\": \"$os_ver\",
            \"hostname\": \"$(scutil --get ComputerName 2>/dev/null || hostname)\",
            \"arch\": \"$(uname -m)\"
        }
    }" >/dev/null 2>&1
    log_daemon "DEBUG" "Heartbeat sent"
}

check_server_commands() {
    local response
    response=$(api_call "/pending-commands" "{\"device_id\": \"$DEVICE_ID\"}" 2>/dev/null) || return

    if [[ -z "$response" ]] || [[ "$response" == "null" ]]; then return; fi

    local cmd_count
    cmd_count=$(/usr/bin/python3 -c "
import json, sys
try:
    d = json.loads('''$response''')
    print(len(d.get('commands', [])))
except:
    print(0)
" 2>/dev/null || echo "0")

    if [[ "$cmd_count" -gt 0 ]]; then
        /usr/bin/python3 -c "
import json
d = json.loads('''$response''')
for cmd in d.get('commands', []):
    print(cmd.get('action', ''))
" 2>/dev/null | while read -r action; do
            log_daemon "INFO" "Server command received: $action"
            case "$action" in
                quick_scan)
                    bash "$OD_DIR/od-clamav-agent.sh" --server-url "$SERVER_URL" --device-id "$DEVICE_ID" --api-key "$API_KEY" --action scan 2>&1 >> "$LOG_FILE" &
                    ;;
                full_scan)
                    bash "$OD_DIR/od-clamav-agent.sh" --server-url "$SERVER_URL" --device-id "$DEVICE_ID" --api-key "$API_KEY" --action scan 2>&1 >> "$LOG_FILE" &
                    ;;
                update_sigs)
                    "$FRESHCLAM_BIN" --config-file="$CONFIG_DIR/freshclam.conf" --datadir="$SIGNATURES_DIR" 2>&1 >> "$LOG_FILE" || true
                    ;;
                *)
                    log_daemon "WARN" "Unknown command: $action"
                    ;;
            esac
        done
    fi
}

# ---- Main loop ----
log_daemon "INFO" "OpenDirectory ClamAV daemon starting"
log_daemon "INFO" "Server: $SERVER_URL | Device: $DEVICE_ID"

# Start clamd if not running
if ! pgrep -x clamd &>/dev/null; then
    if [[ -x "$CLAMD_BIN" ]]; then
        log_daemon "INFO" "Starting clamd..."
        "$CLAMD_BIN" --config-file="$CONFIG_DIR/clamd.conf" 2>/dev/null || log_daemon "WARN" "Failed to start clamd"
    fi
fi

# Initial heartbeat
send_heartbeat

COUNTER=0
while true; do
    sleep 30
    COUNTER=$((COUNTER + 1))

    # Heartbeat every 5 minutes
    if [[ $((COUNTER % 10)) -eq 0 ]]; then
        send_heartbeat
    fi

    # Check server commands every 60 seconds
    if [[ $((COUNTER % 2)) -eq 0 ]]; then
        check_server_commands
    fi

    # Restart clamd if it died
    if ! pgrep -x clamd &>/dev/null; then
        if [[ -x "$CLAMD_BIN" ]]; then
            log_daemon "WARN" "clamd not running, restarting..."
            "$CLAMD_BIN" --config-file="$CONFIG_DIR/clamd.conf" 2>/dev/null || log_daemon "ERROR" "Failed to restart clamd"
        fi
    fi
done
DAEMON_BODY

    chmod +x "$OD_DIR/od-clamav-daemon.sh"

    # ---- Main daemon plist (heartbeat + command polling) ----
    cat > "$PLIST_PATH" <<PLIST_MAIN
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$OD_DIR/od-clamav-daemon.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/clamav-daemon-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/clamav-daemon-stderr.log</string>
    <key>WorkingDirectory</key>
    <string>$OD_DIR</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST_MAIN

    # ---- Quick scan plist ----
    cat > "$PLIST_QUICKSCAN_PATH" <<PLIST_QUICK
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_QUICKSCAN_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$OD_DIR/od-clamav-agent.sh</string>
        <string>--server-url</string>
        <string>$SERVER_URL</string>
        <string>--device-id</string>
        <string>$DEVICE_ID</string>
        <string>--api-key</string>
        <string>$API_KEY</string>
        <string>--action</string>
        <string>scan</string>
    </array>
    <key>StartInterval</key>
    <integer>$quick_interval</integer>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/quickscan-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/quickscan-stderr.log</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST_QUICK

    # ---- Full scan plist (weekly on Sunday at 02:00, or daily for aggressive) ----
    local full_scan_day=0  # Sunday
    local full_scan_hour=2
    local full_scan_minute=0

    cat > "$PLIST_FULLSCAN_PATH" <<PLIST_FULL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_FULLSCAN_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$OD_DIR/od-clamav-agent.sh</string>
        <string>--server-url</string>
        <string>$SERVER_URL</string>
        <string>--device-id</string>
        <string>$DEVICE_ID</string>
        <string>--api-key</string>
        <string>$API_KEY</string>
        <string>--schedule</string>
        <string>full</string>
        <string>--action</string>
        <string>scan</string>
    </array>
    <key>StartCalendarInterval</key>
PLIST_FULL

    if [[ "$SCAN_SCHEDULE" == "aggressive" ]]; then
        # Daily at 02:00
        cat >> "$PLIST_FULLSCAN_PATH" <<PLIST_FULL_DAILY
    <dict>
        <key>Hour</key>
        <integer>$full_scan_hour</integer>
        <key>Minute</key>
        <integer>$full_scan_minute</integer>
    </dict>
PLIST_FULL_DAILY
    else
        # Weekly on Sunday at 02:00
        cat >> "$PLIST_FULLSCAN_PATH" <<PLIST_FULL_WEEKLY
    <dict>
        <key>Weekday</key>
        <integer>$full_scan_day</integer>
        <key>Hour</key>
        <integer>$full_scan_hour</integer>
        <key>Minute</key>
        <integer>$full_scan_minute</integer>
    </dict>
PLIST_FULL_WEEKLY
    fi

    cat >> "$PLIST_FULLSCAN_PATH" <<PLIST_FULL_END
    <key>StandardOutPath</key>
    <string>$LOG_DIR/fullscan-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/fullscan-stderr.log</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>Nice</key>
    <integer>15</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST_FULL_END

    # ---- FreshClam signature update plist (every hour) ----
    cat > "$PLIST_FRESHCLAM_PATH" <<PLIST_FRESHCLAM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_FRESHCLAM_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$FRESHCLAM_BIN</string>
        <string>--config-file=$CONFIG_DIR/freshclam.conf</string>
        <string>--datadir=$SIGNATURES_DIR</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/freshclam-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/freshclam-stderr.log</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
</dict>
</plist>
PLIST_FRESHCLAM

    # Set correct permissions on plists
    for plist in "$PLIST_PATH" "$PLIST_QUICKSCAN_PATH" "$PLIST_FULLSCAN_PATH" "$PLIST_FRESHCLAM_PATH"; do
        chown root:wheel "$plist"
        chmod 644 "$plist"
    done

    # Unload existing services (ignore errors)
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    launchctl unload "$PLIST_QUICKSCAN_PATH" 2>/dev/null || true
    launchctl unload "$PLIST_FULLSCAN_PATH" 2>/dev/null || true
    launchctl unload "$PLIST_FRESHCLAM_PATH" 2>/dev/null || true

    # Load services
    launchctl load "$PLIST_PATH"
    launchctl load "$PLIST_QUICKSCAN_PATH"
    launchctl load "$PLIST_FULLSCAN_PATH"
    launchctl load "$PLIST_FRESHCLAM_PATH"

    log_info "LaunchDaemon services installed and started"
}

# ============================================================
# Copy agent script to OD_DIR
# ============================================================

install_agent_script() {
    # Copy this script to OD_DIR so launchd can reference it
    local script_path
    script_path=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
    if [[ -f "$script_path" ]] && [[ "$script_path" != "$OD_DIR/od-clamav-agent.sh" ]]; then
        cp "$script_path" "$OD_DIR/od-clamav-agent.sh"
        chmod +x "$OD_DIR/od-clamav-agent.sh"
        log_info "Agent script copied to $OD_DIR/od-clamav-agent.sh"
    fi
}

# ============================================================
# Uninstall
# ============================================================

do_uninstall() {
    log_info "Uninstalling OpenDirectory ClamAV Agent..."

    # Stop clamd
    pkill -x clamd 2>/dev/null || true

    # Unload launchd services
    for plist in "$PLIST_PATH" "$PLIST_QUICKSCAN_PATH" "$PLIST_FULLSCAN_PATH" "$PLIST_FRESHCLAM_PATH"; do
        launchctl unload "$plist" 2>/dev/null || true
        rm -f "$plist"
    done

    # Remove daemon script
    rm -f "$OD_DIR/od-clamav-daemon.sh"
    rm -f "$OD_DIR/od-clamav-permissions.sh"

    # Deregister from server
    api_call "/deregister" "{
        \"device_id\": \"$DEVICE_ID\",
        \"platform\": \"macos\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"
    }" >/dev/null 2>&1 || true

    log_info "OpenDirectory ClamAV Agent uninstalled"
    log_info "ClamAV binaries remain installed. Quarantined files at: $QUARANTINE_DIR"
    log_info "Configuration at: $CONFIG_DIR"
}

# ============================================================
# Status
# ============================================================

show_status() {
    echo ""
    echo "OpenDirectory ClamAV Agent Status (macOS)"
    echo "==========================================="
    echo ""

    # ClamAV installation
    if detect_clamav_paths 2>/dev/null; then
        local version
        version=$("$CLAMSCAN_BIN" --version 2>/dev/null | head -1)
        echo "ClamAV Installed:     Yes"
        echo "ClamAV Version:       $version"
        echo "ClamAV Path:          $CLAMSCAN_BIN"
    else
        echo "ClamAV Installed:     No"
    fi

    # Daemon status
    if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
        echo "Agent Service:        Loaded"
    else
        echo "Agent Service:        Not loaded"
    fi

    # clamd
    if pgrep -x clamd &>/dev/null; then
        echo "clamd (Real-time):    Running (PID $(pgrep -x clamd))"
    else
        echo "clamd (Real-time):    Stopped"
    fi

    # Scheduled services
    echo ""
    echo "Scheduled Services:"
    for label in "$PLIST_LABEL" "$PLIST_QUICKSCAN_LABEL" "$PLIST_FULLSCAN_LABEL" "$PLIST_FRESHCLAM_LABEL"; do
        if launchctl list | grep -q "$label" 2>/dev/null; then
            echo "  $label: Loaded"
        else
            echo "  $label: Not loaded"
        fi
    done

    # State
    if [[ -f "$STATE_FILE" ]]; then
        echo ""
        local last_quick last_full last_sig
        last_quick=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_quick_scan','Never'))" 2>/dev/null || echo "Unknown")
        last_full=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_full_scan','Never'))" 2>/dev/null || echo "Unknown")
        last_sig=$(/usr/bin/python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('last_signature_update','Never'))" 2>/dev/null || echo "Unknown")
        echo "Last Quick Scan:      $last_quick"
        echo "Last Full Scan:       $last_full"
        echo "Last Sig Update:      $last_sig"
    fi

    # Quarantine
    local q_count=0
    if [[ -d "$QUARANTINE_DIR" ]]; then
        q_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
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

    # Full Disk Access check
    echo "Permissions:"
    if ls "/Library/Application Support/com.apple.TCC/TCC.db" &>/dev/null 2>&1; then
        echo "  Full Disk Access:   Granted"
    else
        echo "  Full Disk Access:   Not granted (run: sudo $OD_DIR/od-clamav-permissions.sh)"
    fi
    echo ""
}

# ============================================================
# Main Installation
# ============================================================

do_install() {
    echo ""
    echo "OpenDirectory ClamAV Antivirus Agent - macOS"
    echo "============================================="
    echo ""

    create_directories
    install_clamav
    write_clamd_conf
    write_freshclam_conf
    init_state
    install_agent_script
    update_signatures
    handle_macos_permissions
    install_launchd_services

    # Send initial heartbeat
    send_heartbeat

    # Register with server
    local os_version
    os_version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    local hostname_val
    hostname_val=$(scutil --get ComputerName 2>/dev/null || hostname)

    api_call "/register" "{
        \"device_id\": \"$DEVICE_ID\",
        \"platform\": \"macos\",
        \"hostname\": \"$hostname_val\",
        \"os_version\": \"macOS $os_version\",
        \"agent_version\": \"$AGENT_VERSION\",
        \"clamav_path\": \"$CLAMSCAN_BIN\",
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
detect_device_id
detect_clamav_paths 2>/dev/null || true

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
        if [[ "$SCAN_SCHEDULE" == "full" ]]; then
            run_scan "full"
        else
            run_scan "quick"
        fi
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
