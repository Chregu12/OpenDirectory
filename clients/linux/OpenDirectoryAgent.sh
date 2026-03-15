#!/bin/bash
# ============================================================================
# OpenDirectory Linux Agent
# Persistent WebSocket connection to server - receives commands & notifications
# Server pushes to agent (no polling)
# ============================================================================

set -euo pipefail

AGENT_VERSION="2.0.0"
PLATFORM="linux"
OD_PATH="/opt/opendirectory"
LOG_PATH="$OD_PATH/logs/agent"
CONFIG_PATH="$OD_PATH/device-config.json"
SERVICE_NAME="opendirectory-agent"
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
    find "$LOG_PATH" -name "agent-*.log" -mtime +14 -delete 2>/dev/null || true
}

# ============================================================================
# CONFIGURATION
# ============================================================================
get_device_id() {
    if [ -f "$CONFIG_PATH" ]; then
        python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('device_id',''))" 2>/dev/null && return
    fi
    # Fallback: machine-id
    cat /etc/machine-id 2>/dev/null || hostname
}

get_server_url() {
    if [ -f "$CONFIG_PATH" ]; then
        python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('server_url','https://mdm.opendirectory.local'))" 2>/dev/null
    else
        echo "https://mdm.opendirectory.local"
    fi
}

# ============================================================================
# NOTIFICATIONS (Linux: notify-send / libnotify)
# ============================================================================
show_notification() {
    local title="$1"
    local body="$2"
    local urgency="${3:-normal}"  # low, normal, critical

    # Try notify-send (works on most Linux desktops)
    if command -v notify-send &>/dev/null; then
        # Run as the logged-in user (agent runs as root)
        local user
        user=$(who | head -1 | awk '{print $1}')
        if [ -n "$user" ]; then
            local uid
            uid=$(id -u "$user" 2>/dev/null)
            if [ -n "$uid" ]; then
                sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
                    notify-send --urgency="$urgency" --app-name="OpenDirectory" "$title" "$body" 2>/dev/null || true
            fi
        else
            notify-send --urgency="$urgency" --app-name="OpenDirectory" "$title" "$body" 2>/dev/null || true
        fi
    fi

    # Also log via systemd journal if available
    if command -v logger &>/dev/null; then
        logger -t "opendirectory-agent" "[$urgency] $title: $body"
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
            show_notification "App aktualisiert: $app_name" "Update erfolgreich installiert."
            ;;
        app_installed)
            local app_name
            app_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_name',''))" 2>/dev/null)
            show_notification "App installiert: $app_name" "Erfolgreich installiert."
            ;;
        compliance_violation)
            local rule
            rule=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('rule',''))" 2>/dev/null)
            show_notification "Compliance-Verstoss" "$rule" "critical"
            ;;
        compliance_restored)
            show_notification "Compliance OK" "Alle Richtlinien erfuellt."
            ;;
        policy_deployed|policy_changed)
            local policy_name
            policy_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policy_name',''))" 2>/dev/null)
            show_notification "Richtlinie: $policy_name" "Richtlinie wurde angewendet."
            ;;
        security_alert)
            local body
            body=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('body','Sicherheitswarnung'))" 2>/dev/null)
            show_notification "Sicherheitswarnung" "$body" "critical"
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
            show_notification "Installiere $app_name..." "Bitte warten."

            # Detect package manager
            if command -v apt-get &>/dev/null; then
                output=$(DEBIAN_FRONTEND=noninteractive apt-get install -y "$app_id" 2>&1) || status="failed"
            elif command -v dnf &>/dev/null; then
                output=$(dnf install -y "$app_id" 2>&1) || status="failed"
            elif command -v snap &>/dev/null; then
                output=$(snap install "$app_id" 2>&1) || status="failed"
            elif command -v flatpak &>/dev/null; then
                output=$(flatpak install -y "$app_id" 2>&1) || status="failed"
            else
                status="failed"; output="No supported package manager found"
            fi

            [ "$status" = "completed" ] && show_notification "Installiert: $app_name" "Erfolgreich."
            [ "$status" = "failed" ] && show_notification "Fehlgeschlagen: $app_name" "Installation fehlgeschlagen." "critical"
            ;;
        update_app)
            local app_id
            app_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('app_id',''))" 2>/dev/null)
            if command -v apt-get &>/dev/null; then
                output=$(DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y "$app_id" 2>&1) || status="failed"
            elif command -v dnf &>/dev/null; then
                output=$(dnf upgrade -y "$app_id" 2>&1) || status="failed"
            else
                status="failed"; output="No supported package manager"
            fi
            ;;
        sync_policies)
            local server_url device_id
            server_url=$(get_server_url); device_id=$(get_device_id)
            output=$(curl -sf "$server_url/api/v1/devices/$device_id/policies" 2>&1) || status="failed"
            show_notification "Richtlinien synchronisiert" "Policies angewendet."
            ;;
        collect_inventory)
            output=$(get_inventory)
            ;;
        show_notification)
            handle_notification "$json"
            output="Notification shown"
            ;;
        *)
            status="failed"; output="Unknown command: $cmd_type"
            ;;
    esac

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
    'platform': 'linux',
    'os': {
        'name': platform.system(),
        'version': platform.release(),
        'distro': subprocess.getoutput('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d \\'\"\\'' '),
        'arch': platform.machine()
    },
    'hardware': {
        'cpu': subprocess.getoutput('cat /proc/cpuinfo | grep \"model name\" | head -1 | cut -d: -f2').strip(),
        'ram_gb': round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024**3), 1),
        'disk_free_gb': round(os.statvfs('/').f_bavail * os.statvfs('/').f_frsize / (1024**3), 1)
    },
    'package_managers': {
        'apt': os.path.exists('/usr/bin/apt-get'),
        'dnf': os.path.exists('/usr/bin/dnf'),
        'snap': os.path.exists('/usr/bin/snap'),
        'flatpak': os.path.exists('/usr/bin/flatpak')
    }
}
print(json.dumps(inv, indent=2))
" 2>/dev/null
}

# ============================================================================
# WEBSOCKET CLIENT (Python3-based, same pattern as macOS)
# ============================================================================
start_agent_loop() {
    local server_url device_id reconnect_delay ws_url
    server_url=$(get_server_url)
    device_id=$(get_device_id)
    reconnect_delay=$RECONNECT_DELAY
    ws_url=$(echo "$server_url" | sed 's|^https://|wss://|; s|^http://|ws://|')
    ws_url="${ws_url}/ws/devices"

    log "========================================="
    log "OpenDirectory Agent v$AGENT_VERSION (WebSocket)"
    log "Device ID: $device_id"
    log "Server: $server_url"
    log "WebSocket: $ws_url"
    log "Platform: $PLATFORM"
    log "========================================="

    show_notification "OpenDirectory Agent" "Agent gestartet, verbinde mit Server..."

    # Ensure websockets module is installed
    python3 -c "import websockets" 2>/dev/null || python3 -m pip install --quiet websockets 2>/dev/null

    while true; do
        log "Connecting to $ws_url"

        python3 -u << PYEOF "$ws_url" "$device_id" "$AGENT_VERSION" "$PLATFORM" 2>&1 | while IFS= read -r line; do
import sys, json, asyncio

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

        async def heartbeat():
            while True:
                await asyncio.sleep(30)
                await ws.send(json.dumps({
                    "type": "device_heartbeat",
                    "data": {"deviceId": device_id}
                }))

        hb_task = asyncio.create_task(heartbeat())
        try:
            async for raw in ws:
                msg = json.loads(raw)
                print(f"MSG:{json.dumps(msg)}", flush=True)
        finally:
            hb_task.cancel()

try:
    asyncio.run(agent())
except Exception as e:
    print(f"ERROR:{e}", flush=True)
    sys.exit(1)
PYEOF

            if [[ "$line" == "CONNECTED" ]]; then
                log "WebSocket connected"
                show_notification "OpenDirectory Agent" "Verbunden mit Server."
                reconnect_delay=$RECONNECT_DELAY
            elif [[ "$line" == MSG:* ]]; then
                local msg_json="${line#MSG:}"
                local msg_type
                msg_type=$(echo "$msg_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type',''))" 2>/dev/null)
                case "$msg_type" in
                    notification)       handle_notification "$msg_json" ;;
                    command)            handle_command "$msg_json" >/dev/null ;;
                    heartbeat_ack|agent_registered|connection) log "Server: $msg_type" ;;
                    *)                  log "Unknown: $msg_type" "DEBUG" ;;
                esac
            elif [[ "$line" == ERROR:* ]]; then
                log "WebSocket error: ${line#ERROR:}" "ERROR"
            fi
        done

        log "Reconnecting in ${reconnect_delay}s..."
        sleep "$reconnect_delay"
        reconnect_delay=$((reconnect_delay * 2))
        [ "$reconnect_delay" -gt "$MAX_RECONNECT_DELAY" ] && reconnect_delay=$MAX_RECONNECT_DELAY
    done
}

# ============================================================================
# INSTALLATION (systemd service)
# ============================================================================
install_agent() {
    echo "Installing OpenDirectory Agent v$AGENT_VERSION..."
    mkdir -p "$OD_PATH" "$LOG_PATH" "$OD_PATH/scripts" "$OD_PATH/config"

    local agent_dest="$OD_PATH/OpenDirectoryAgent.sh"
    cp "$0" "$agent_dest"
    chmod +x "$agent_dest"

    # Create systemd service
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=OpenDirectory Agent - WebSocket-based device management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash $agent_dest run
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    echo "Agent installed and started (WebSocket mode)"
    echo "Service: $SERVICE_NAME | Logs: journalctl -u $SERVICE_NAME"
}

uninstall_agent() {
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    rm -f "$OD_PATH/OpenDirectoryAgent.sh"
    echo "Agent uninstalled (config/logs preserved)"
}

# ============================================================================
case "$ACTION" in
    install)   install_agent ;;
    uninstall) uninstall_agent ;;
    status)    systemctl status "$SERVICE_NAME" 2>/dev/null || echo "Not installed" ;;
    run)       start_agent_loop ;;
    *)         echo "Usage: $0 {install|uninstall|run|status}" ;;
esac
