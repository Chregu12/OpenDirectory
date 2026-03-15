#!/bin/bash
# ============================================================================
# OpenDirectory macOS Agent
# Persistent WebSocket connection to server - receives commands & notifications
# Server pushes to agent (no polling)
# ============================================================================

set -euo pipefail

AGENT_VERSION="2.0.0"
PLATFORM="macos"
OD_PATH="/Library/OpenDirectory"
LOG_PATH="$OD_PATH/Logs/Agent"
CONFIG_PATH="$OD_PATH/device-config.json"
PLIST_LABEL="com.opendirectory.agent"
PLIST_PATH="/Library/LaunchDaemons/$PLIST_LABEL.plist"
HEARTBEAT_INTERVAL=30
RECONNECT_DELAY=5
MAX_RECONNECT_DELAY=300
ACTION="${1:-run}"

# ============================================================================
# LOGGING
# ============================================================================
log() {
    local level="${2:-INFO}"
    local logfile="$LOG_PATH/agent-$(date +%Y%m%d).log"
    mkdir -p "$LOG_PATH"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $1" >> "$logfile"
    # Rotate logs older than 14 days
    find "$LOG_PATH" -name "agent-*.log" -mtime +14 -delete 2>/dev/null || true
}

# ============================================================================
# CONFIGURATION
# ============================================================================
get_device_id() {
    if [ -f "$CONFIG_PATH" ]; then
        python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('device_id',''))" 2>/dev/null
    fi
    # Fallback: hardware UUID
    if [ -z "${DEVICE_ID:-}" ]; then
        ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $(NF-1)}'
    fi
}

get_server_url() {
    if [ -f "$CONFIG_PATH" ]; then
        python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('server_url','https://mdm.opendirectory.local'))" 2>/dev/null
    else
        echo "https://mdm.opendirectory.local"
    fi
}

get_ws_url() {
    local url
    url=$(get_server_url)
    echo "$url" | sed 's|^https://|wss://|; s|^http://|ws://|'
    echo "/ws/devices"
}

# ============================================================================
# NOTIFICATIONS (macOS-specific: osascript/terminal-notifier)
# ============================================================================
show_notification() {
    local title="$1"
    local body="$2"
    local subtitle="${3:-OpenDirectory}"

    # Try terminal-notifier first (richer notifications)
    if command -v terminal-notifier &>/dev/null; then
        terminal-notifier -title "$title" -message "$body" -subtitle "$subtitle" \
            -sender "com.opendirectory.agent" -group "opendirectory" 2>/dev/null || true
    else
        # Fallback to osascript
        osascript -e "display notification \"$body\" with title \"$title\" subtitle \"$subtitle\"" 2>/dev/null || true
    fi
    log "Notification: $title - $body"
}

# ============================================================================
# NOTIFICATION HANDLER (generic message format from server)
# ============================================================================
handle_notification() {
    local json="$1"
    local category
    category=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('category',''))" 2>/dev/null)

    case "$category" in
        app_update)
            local app_name
            app_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_name',''))" 2>/dev/null)
            show_notification "App aktualisiert: $app_name" "Update erfolgreich installiert." "OpenDirectory - Updates"
            ;;
        app_installed)
            local app_name
            app_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_name',''))" 2>/dev/null)
            show_notification "App installiert: $app_name" "Erfolgreich installiert." "OpenDirectory - Software"
            ;;
        compliance_violation)
            local rule
            rule=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('rule',''))" 2>/dev/null)
            show_notification "Compliance-Verstoss" "$rule" "OpenDirectory - Compliance"
            ;;
        compliance_restored)
            show_notification "Compliance OK" "Alle Richtlinien erfuellt." "OpenDirectory - Compliance"
            ;;
        policy_deployed|policy_changed)
            local policy_name
            policy_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policy_name',''))" 2>/dev/null)
            show_notification "Richtlinie: $policy_name" "Richtlinie wurde angewendet." "OpenDirectory - Policies"
            ;;
        security_alert)
            local body
            body=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('body','Sicherheitswarnung'))" 2>/dev/null)
            show_notification "Sicherheitswarnung" "$body" "OpenDirectory - Sicherheit"
            ;;
        *)
            local title body
            title=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('title','OpenDirectory'))" 2>/dev/null)
            body=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('body',''))" 2>/dev/null)
            [ -n "$body" ] && show_notification "$title" "$body"
            ;;
    esac
}

# ============================================================================
# COMMAND EXECUTION
# ============================================================================
handle_command() {
    local json="$1"
    local cmd_type cmd_id output status="completed"

    cmd_type=$(echo "$json" | python3 -c "import sys,json; m=json.load(sys.stdin); print(m.get('command_type',m.get('type','')))" 2>/dev/null)
    cmd_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

    log "Executing command: $cmd_type (ID: $cmd_id)"

    case "$cmd_type" in
        run_script)
            local script
            script=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('script',''))" 2>/dev/null)
            output=$(eval "$script" 2>&1) || status="failed"
            ;;
        install_app)
            local app_id app_name
            app_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_id',''))" 2>/dev/null)
            app_name=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin).get('data',{}); print(d.get('app_name',d.get('app_id','')))" 2>/dev/null)
            show_notification "Installiere $app_name..." "Bitte warten." "OpenDirectory"
            if command -v brew &>/dev/null; then
                output=$(brew install --cask "$app_id" 2>&1) || output=$(brew install "$app_id" 2>&1) || status="failed"
            else
                status="failed"; output="Homebrew not installed"
            fi
            [ "$status" = "completed" ] && show_notification "Installiert: $app_name" "Erfolgreich." "OpenDirectory"
            [ "$status" = "failed" ] && show_notification "Fehlgeschlagen: $app_name" "Installation fehlgeschlagen." "OpenDirectory"
            ;;
        update_app)
            local app_id
            app_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_id',''))" 2>/dev/null)
            if command -v brew &>/dev/null; then
                output=$(brew upgrade "$app_id" 2>&1) || status="failed"
            else
                status="failed"; output="Homebrew not installed"
            fi
            ;;
        sync_policies)
            local server_url device_id
            server_url=$(get_server_url); device_id=$(get_device_id)
            output=$(curl -s "$server_url/api/v1/devices/$device_id/policies" 2>&1) || status="failed"
            show_notification "Richtlinien synchronisiert" "Policies angewendet." "OpenDirectory"
            ;;
        collect_inventory)
            output=$(get_inventory)
            ;;
        show_notification)
            handle_notification "$json"
            output="Notification shown"
            ;;

        # ── Printer Commands (macOS: lpadmin / CUPS) ──────────────────
        deploy_printers)
            output=$(handle_deploy_printers "$json") || status="failed"
            ;;
        remove_printer)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            output=$(handle_remove_printer "$pname") || status="failed"
            ;;
        set_default_printer)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            output=$(handle_set_default_printer "$pname") || status="failed"
            ;;
        list_printers)
            output=$(handle_list_printers)
            ;;
        get_printer_status)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            output=$(handle_get_printer_status "$pname")
            ;;
        update_printer_settings)
            output=$(handle_update_printer_settings "$json") || status="failed"
            ;;
        apply_printer_policy)
            output=$(handle_apply_printer_policy "$json") || status="failed"
            ;;
        set_printer_paused)
            local pname paused
            pname=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin).get('data',{}); print(d.get('printerName',''))" 2>/dev/null)
            paused=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('paused',False))" 2>/dev/null)
            [ "$pname" != "OD_"* ] && pname="OD_$pname"
            if [ "$paused" = "True" ]; then
                output=$(cupsdisable "$pname" 2>&1) || status="failed"
            else
                output=$(cupsenable "$pname" 2>&1) || status="failed"
            fi
            ;;
        cancel_print_job)
            local job_id
            job_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('jobId',''))" 2>/dev/null)
            output=$(cancel "$job_id" 2>&1) || status="failed"
            ;;
        clear_print_queue)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            [ "$pname" != "OD_"* ] && pname="OD_$pname"
            output=$(cancel -a "$pname" 2>&1) || status="failed"
            ;;
        test_print)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            [ "$pname" != "OD_"* ] && pname="OD_$pname"
            output=$(echo "OpenDirectory Test Print - $(date) - $(hostname) - $pname" | lp -d "$pname" 2>&1) || status="failed"
            ;;

        *)
            status="failed"; output="Unknown command: $cmd_type"
            ;;
    esac

    # Send result back via WebSocket
    echo "{\"type\":\"command_result\",\"data\":{\"commandId\":\"$cmd_id\",\"status\":\"$status\",\"output\":$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')}}"
}

# ============================================================================
# DEVICE INVENTORY
# ============================================================================
get_inventory() {
    python3 -c "
import json, subprocess, platform, os
inv = {
    'device_id': '$(get_device_id)',
    'hostname': platform.node(),
    'platform': 'macos',
    'os': {
        'name': 'macOS',
        'version': platform.mac_ver()[0],
        'arch': platform.machine()
    },
    'hardware': {
        'cpu': subprocess.getoutput('sysctl -n machdep.cpu.brand_string'),
        'ram_gb': round(int(subprocess.getoutput('sysctl -n hw.memsize')) / (1024**3), 1)
    },
    'homebrew': {
        'installed': os.path.exists('/opt/homebrew/bin/brew') or os.path.exists('/usr/local/bin/brew')
    }
}
print(json.dumps(inv, indent=2))
" 2>/dev/null
}

# ============================================================================
# PRINTER MANAGEMENT (macOS: lpadmin / CUPS)
# ============================================================================
build_printer_uri() {
    local address="$1" protocol="$2" port="$3"
    case "${protocol,,}" in
        ipp)   echo "ipp://$address:${port:-631}/ipp/print" ;;
        ipps)  echo "ipps://$address:${port:-631}/ipp/print" ;;
        lpd)   echo "lpd://$address/" ;;
        socket|raw) echo "socket://$address:${port:-9100}" ;;
        smb)   echo "smb://$address/" ;;
        *)     echo "ipp://$address:${port:-631}/ipp/print" ;;
    esac
}

install_single_printer() {
    local name="$1" address="$2" protocol="$3" driver="$4" location="$5" description="$6" port="$7"
    local pname="OD_$name"
    local uri
    uri=$(build_printer_uri "$address" "$protocol" "$port")

    # Remove existing
    lpadmin -x "$pname" 2>/dev/null || true

    # Add printer
    if [ -z "$driver" ] || [ "$driver" = "auto" ] || [ "$driver" = "null" ]; then
        lpadmin -p "$pname" -E -v "$uri" -m everywhere 2>&1
    else
        lpadmin -p "$pname" -E -v "$uri" -m "$driver" 2>&1
    fi

    [ -n "$location" ] && [ "$location" != "null" ] && lpadmin -p "$pname" -L "$location" 2>/dev/null
    [ -n "$description" ] && [ "$description" != "null" ] && lpadmin -p "$pname" -D "$description" 2>/dev/null

    cupsenable "$pname" 2>/dev/null
    cupsaccept "$pname" 2>/dev/null

    log "Printer installed: $pname → $uri"
}

handle_deploy_printers() {
    local json="$1"
    python3 -c "
import sys, json, subprocess

data = json.load(sys.stdin).get('data', {})
printers = data.get('printers', [])
remove_existing = data.get('removeExisting', False)
set_default = data.get('setDefault')
notify = data.get('notifyUser', True)
results = []

if remove_existing:
    out = subprocess.getoutput('lpstat -p 2>/dev/null')
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith('OD_'):
            subprocess.run(['lpadmin', '-x', parts[1]], capture_output=True)

for p in printers:
    name = p.get('name', '')
    pname = f'OD_{name}'
    addr = p.get('address', '')
    proto = p.get('protocol', 'ipp')
    driver = p.get('driver', 'auto')
    location = p.get('location', '')
    desc = p.get('description', '')
    port = p.get('port', '')
    is_default = p.get('isDefault', False)

    try:
        subprocess.run(['lpadmin', '-x', pname], capture_output=True)

        uri_map = {'ipp': f'ipp://{addr}:{port or 631}/ipp/print',
                    'ipps': f'ipps://{addr}:{port or 631}/ipp/print',
                    'lpd': f'lpd://{addr}/',
                    'socket': f'socket://{addr}:{port or 9100}',
                    'raw': f'socket://{addr}:{port or 9100}'}
        uri = uri_map.get(proto, f'ipp://{addr}:{port or 631}/ipp/print')

        if not driver or driver in ('auto', 'null'):
            subprocess.run(['lpadmin', '-p', pname, '-E', '-v', uri, '-m', 'everywhere'], check=True, capture_output=True)
        else:
            subprocess.run(['lpadmin', '-p', pname, '-E', '-v', uri, '-m', driver], check=True, capture_output=True)

        if location:
            subprocess.run(['lpadmin', '-p', pname, '-L', location], capture_output=True)
        if desc:
            subprocess.run(['lpadmin', '-p', pname, '-D', desc], capture_output=True)

        subprocess.run(['cupsenable', pname], capture_output=True)
        subprocess.run(['cupsaccept', pname], capture_output=True)

        if is_default or name == set_default:
            subprocess.run(['lpadmin', '-d', pname], capture_output=True)

        results.append({'name': pname, 'status': 'installed'})
    except Exception as e:
        results.append({'name': pname, 'status': 'failed', 'error': str(e)})

print(json.dumps({'printers': results}))
" <<< "$json"

    local notify_user
    notify_user=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('notifyUser',True))" 2>/dev/null)
    [ "$notify_user" != "False" ] && show_notification "Drucker konfiguriert" "Drucker wurden installiert." "OpenDirectory - Drucker"
}

handle_remove_printer() {
    local pname="$1"
    [[ "$pname" != OD_* ]] && pname="OD_$pname"
    if lpstat -p "$pname" &>/dev/null; then
        lpadmin -x "$pname" 2>&1
        log "Printer removed: $pname"
        show_notification "Drucker entfernt" "$pname" "OpenDirectory - Drucker"
        echo "Removed: $pname"
    else
        echo "Printer not found: $pname"
    fi
}

handle_set_default_printer() {
    local pname="$1"
    [[ "$pname" != OD_* ]] && pname="OD_$pname"
    lpadmin -d "$pname" 2>&1
    log "Default printer set: $pname"
    echo "Default printer: $pname"
}

handle_list_printers() {
    python3 -c "
import subprocess, json
out = subprocess.getoutput('lpstat -p -d 2>/dev/null')
printers = []
default_printer = ''
for line in out.splitlines():
    if line.startswith('printer '):
        parts = line.split()
        name = parts[1] if len(parts) >= 2 else ''
        status = 'idle' if 'idle' in line else 'busy' if 'printing' in line else 'disabled' if 'disabled' in line else 'unknown'
        printers.append({'name': name, 'status': status})
    if 'system default destination' in line:
        default_printer = line.split(':')[-1].strip()
for p in printers:
    p['isDefault'] = (p['name'] == default_printer)
print(json.dumps(printers))
"
}

handle_get_printer_status() {
    local pname="$1"
    [[ "$pname" != OD_* ]] && pname="OD_$pname"
    python3 -c "
import subprocess, json
pname = '$pname'
info = subprocess.getoutput(f'lpstat -p {pname} -l 2>/dev/null')
jobs_out = subprocess.getoutput(f'lpstat -o {pname} 2>/dev/null')
jobs = []
for line in jobs_out.splitlines():
    parts = line.split()
    if len(parts) >= 4:
        jobs.append({'id': parts[0], 'user': parts[1], 'size': parts[2]})
print(json.dumps({'name': pname, 'info': info, 'jobs': jobs, 'jobCount': len(jobs)}))
"
}

handle_update_printer_settings() {
    local json="$1"
    python3 -c "
import sys, json, subprocess
data = json.load(sys.stdin).get('data', {})
pname = data.get('printerName', '')
if not pname.startswith('OD_'): pname = f'OD_{pname}'
settings = data.get('settings', {})
if settings.get('location'):
    subprocess.run(['lpadmin', '-p', pname, '-L', settings['location']], capture_output=True)
if settings.get('description') or settings.get('comment'):
    subprocess.run(['lpadmin', '-p', pname, '-D', settings.get('description', settings.get('comment', ''))], capture_output=True)
if settings.get('duplex'):
    duplex_map = {'long': 'DuplexNoTumble', 'short': 'DuplexTumble', 'none': 'None'}
    val = duplex_map.get(settings['duplex'], 'None')
    subprocess.run(['lpoptions', '-p', pname, '-o', f'sides={val}'], capture_output=True)
if settings.get('color') is not None:
    val = 'Color' if settings['color'] else 'Gray'
    subprocess.run(['lpoptions', '-p', pname, '-o', f'ColorModel={val}'], capture_output=True)
print(f'Settings updated: {pname}')
" <<< "$json"
}

handle_apply_printer_policy() {
    local json="$1"
    # Remove unmanaged printers if policy requires
    local remove_unmanaged
    remove_unmanaged=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('removeUnmanaged',False))" 2>/dev/null)
    if [ "$remove_unmanaged" = "True" ]; then
        local managed_names
        managed_names=$(echo "$json" | python3 -c "
import sys,json
printers = json.load(sys.stdin).get('data',{}).get('printers',[])
print(' '.join(['OD_' + p.get('name','') for p in printers]))
" 2>/dev/null)
        lpstat -p 2>/dev/null | awk '/^printer OD_/{print $2}' | while read -r existing; do
            if ! echo " $managed_names " | grep -q " $existing "; then
                lpadmin -x "$existing" 2>/dev/null
                log "Policy: removed unmanaged printer $existing"
            fi
        done
    fi
    # Deploy policy printers
    handle_deploy_printers "$json"
    local policy_id
    policy_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policyId',''))" 2>/dev/null)
    [ -n "$policy_id" ] && [ "$policy_id" != "None" ] && show_notification "Drucker-Richtlinie angewendet" "Drucker gemäss Policy konfiguriert." "OpenDirectory - Policies"
}

# ============================================================================
# WEBSOCKET CLIENT (uses websocat or python3 websockets)
# ============================================================================
start_agent_loop() {
    local server_url ws_url device_id reconnect_delay
    server_url=$(get_server_url)
    device_id=$(get_device_id)
    reconnect_delay=$RECONNECT_DELAY

    # Convert URL for WebSocket
    ws_url=$(echo "$server_url" | sed 's|^https://|wss://|; s|^http://|ws://|')
    ws_url="${ws_url}/ws/devices"

    log "========================================="
    log "OpenDirectory Agent v$AGENT_VERSION (WebSocket)"
    log "Device ID: $device_id"
    log "Server: $server_url"
    log "WebSocket: $ws_url"
    log "Platform: $PLATFORM"
    log "========================================="

    show_notification "OpenDirectory Agent" "Agent gestartet, verbinde mit Server..." "OpenDirectory"

    # Reconnect loop
    while true; do
        log "Connecting to $ws_url"

        # Use Python3 websocket client (available on macOS by default)
        python3 -u << 'PYEOF' "$ws_url" "$device_id" "$AGENT_VERSION" "$PLATFORM" "$OD_PATH" 2>&1 | while IFS= read -r line; do
import sys, json, asyncio, signal, time

try:
    import websockets
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'websockets'])
    import websockets

ws_url = sys.argv[1]
device_id = sys.argv[2]
agent_version = sys.argv[3]
platform_name = sys.argv[4]

async def agent():
    headers = {
        "X-Device-Id": device_id,
        "X-Device-Platform": platform_name,
        "X-Agent-Version": agent_version
    }

    async with websockets.connect(ws_url, extra_headers=headers, ping_interval=30) as ws:
        # Register
        await ws.send(json.dumps({
            "type": "agent_register",
            "data": {
                "deviceId": device_id,
                "platform": platform_name,
                "agentVersion": agent_version,
                "hostname": __import__('platform').node()
            }
        }))
        print("CONNECTED", flush=True)

        # Heartbeat task
        async def heartbeat():
            while True:
                await asyncio.sleep(30)
                await ws.send(json.dumps({
                    "type": "device_heartbeat",
                    "data": {"deviceId": device_id, "timestamp": __import__('datetime').datetime.now().isoformat()}
                }))

        hb_task = asyncio.create_task(heartbeat())

        try:
            async for raw in ws:
                msg = json.loads(raw)
                # Output message type and JSON for the bash handler
                print(f"MSG:{json.dumps(msg)}", flush=True)
        finally:
            hb_task.cancel()

try:
    asyncio.run(agent())
except Exception as e:
    print(f"ERROR:{e}", flush=True)
    sys.exit(1)
PYEOF

            # Process output from Python WebSocket client
            if [[ "$line" == "CONNECTED" ]]; then
                log "WebSocket connected"
                show_notification "OpenDirectory Agent" "Verbunden mit Server." "OpenDirectory"
                reconnect_delay=$RECONNECT_DELAY
            elif [[ "$line" == MSG:* ]]; then
                local msg_json="${line#MSG:}"
                local msg_type
                msg_type=$(echo "$msg_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type',''))" 2>/dev/null)

                case "$msg_type" in
                    notification)
                        handle_notification "$msg_json"
                        ;;
                    command)
                        local result
                        result=$(handle_command "$msg_json")
                        # Result will be sent back by the Python process in next iteration
                        log "Command processed"
                        ;;
                    heartbeat_ack|agent_registered|connection)
                        log "Server: $msg_type"
                        ;;
                    *)
                        log "Unknown message type: $msg_type" "DEBUG"
                        ;;
                esac
            elif [[ "$line" == ERROR:* ]]; then
                log "WebSocket error: ${line#ERROR:}" "ERROR"
            fi
        done

        # Connection lost
        log "Reconnecting in ${reconnect_delay}s..."
        sleep "$reconnect_delay"
        reconnect_delay=$((reconnect_delay * 2))
        [ "$reconnect_delay" -gt "$MAX_RECONNECT_DELAY" ] && reconnect_delay=$MAX_RECONNECT_DELAY
    done
}

# ============================================================================
# INSTALLATION (LaunchDaemon)
# ============================================================================
install_agent() {
    echo "Installing OpenDirectory Agent v$AGENT_VERSION..."
    mkdir -p "$OD_PATH" "$LOG_PATH" "$OD_PATH/Scripts" "$OD_PATH/Config"

    local agent_dest="$OD_PATH/OpenDirectoryAgent.sh"
    cp "$0" "$agent_dest"
    chmod +x "$agent_dest"

    # Create LaunchDaemon plist
    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$agent_dest</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_PATH/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_PATH/stderr.log</string>
</dict>
</plist>
EOF

    launchctl load -w "$PLIST_PATH" 2>/dev/null || true
    echo "Agent installed and started (WebSocket mode)"
    echo "Logs: $LOG_PATH"
}

uninstall_agent() {
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
    rm -f "$OD_PATH/OpenDirectoryAgent.sh"
    echo "Agent uninstalled (config/logs preserved)"
}

# ============================================================================
case "$ACTION" in
    install)   install_agent ;;
    uninstall) uninstall_agent ;;
    status)    launchctl list | grep opendirectory || echo "Not running" ;;
    run)       start_agent_loop ;;
    *)         echo "Usage: $0 {install|uninstall|run|status}" ;;
esac
