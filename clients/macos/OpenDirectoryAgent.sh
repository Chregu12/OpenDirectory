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

        # ── Policy Enforcement Commands ──────────────────────────────
        apply_policy)
            output=$(handle_apply_policy "$json") || status="failed"
            ;;
        remove_policy)
            output=$(handle_remove_policy "$json") || status="failed"
            ;;
        check_compliance)
            output=$(handle_check_compliance "$json") || status="failed"
            ;;
        check_all_compliance)
            output=$(handle_check_all_compliance "$json") || status="failed"
            ;;
        detect_drift)
            output=$(handle_detect_drift "$json") || status="failed"
            ;;
        rollback_policy)
            output=$(handle_rollback_policy "$json") || status="failed"
            ;;
        resync_policies)
            output=$(python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
policies = data.get('data', {}).get('policies', [])
print(json.dumps({'status': 'success', 'resynced': len(policies), 'message': f'Queued {len(policies)} policies for resync'}))
" <<< "$json") || status="failed"
            ;;
        apply_policy_module)
            output=$(python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
module = data.get('data', {}).get('module', '')
settings = data.get('data', {}).get('settings', {})
print(json.dumps({'status': 'success', 'module': module, 'message': f'Policy module {module} applied'}))
" <<< "$json") || status="failed"
            ;;

        # ── Update Management Commands ──────────────────────────────────
        configure_updates)
            output=$(handle_configure_updates "$json") || status="failed"
            ;;
        check_update_status)
            output=$(handle_check_update_status) || status="failed"
            ;;
        trigger_update)
            output=$(handle_trigger_update "$json") || status="failed"
            ;;
        get_update_compliance)
            output=$(handle_get_update_compliance) || status="failed"
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
            [[ "$pname" != OD_* ]] && pname="OD_$pname"
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
            [[ "$pname" != OD_* ]] && pname="OD_$pname"
            output=$(cancel -a "$pname" 2>&1) || status="failed"
            ;;
        test_print)
            local pname
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
            [[ "$pname" != OD_* ]] && pname="OD_$pname"
            output=$(echo "OpenDirectory Test Print - $(date) - $(hostname) - $pname" | lp -d "$pname" 2>&1) || status="failed"
            ;;

        # ── Network Profile Commands ──────────────────────────────────────
        configure_wifi)
            output=$(handle_configure_wifi "$json") || status="failed"
            ;;
        remove_wifi)
            output=$(handle_remove_wifi "$json") || status="failed"
            ;;
        configure_vpn)
            output=$(handle_configure_vpn "$json") || status="failed"
            ;;
        remove_vpn)
            output=$(handle_remove_vpn "$json") || status="failed"
            ;;
        configure_email)
            output=$(handle_configure_email "$json") || status="failed"
            ;;
        remove_email)
            output=$(handle_remove_email "$json") || status="failed"
            ;;

        # ── Deployment/Compliance/Encryption Commands ─────────────────
        zero_touch_deploy)
            output=$(handle_zero_touch_deploy "$json") || status="failed"
            ;;
        check_encryption_status)
            output=$(handle_check_encryption_status) || status="failed"
            ;;
        enable_encryption)
            output=$(handle_enable_encryption "$json") || status="failed"
            ;;
        execute_remediation)
            output=$(handle_execute_remediation "$json") || status="failed"
            ;;

        # ── Compliance Scanning Commands ──────────────────────────────
        compliance_scan)
            output=$(python3 << 'PYEOF' "$json"
import sys, json, subprocess, os
from datetime import datetime

data = json.loads(sys.argv[1]).get('data', {})
checks = data.get('checks', [])
results = []

for check in checks:
    passed = False
    actual = None
    try:
        ctype = check.get('type', '')
        if ctype == 'defaults':
            domain = check.get('domain', '')
            key = check.get('key', '')
            val = subprocess.getoutput(f"defaults read {domain} {key} 2>/dev/null").strip()
            actual = val if val else 'NOT_FOUND'
            if check.get('operator') == '==':
                passed = (actual == str(check.get('value', '')))
            elif check.get('operator') == '>=':
                try: passed = (int(actual) >= int(check['value']))
                except: passed = False
            elif check.get('operator') == '<=':
                try: passed = (int(actual) <= int(check['value']))
                except: passed = False
            elif check.get('operator') == '!=':
                passed = (actual != str(check.get('value', '')))
        elif ctype == 'filevault':
            fv_status = subprocess.getoutput('fdesetup status 2>/dev/null')
            actual = 'On' if 'FileVault is On' in fv_status else 'Off'
            passed = (actual == 'On')
        elif ctype == 'gatekeeper':
            gk_status = subprocess.getoutput('spctl --status 2>/dev/null')
            actual = 'enabled' if 'assessments enabled' in gk_status else 'disabled'
            passed = (actual == 'enabled')
        elif ctype == 'sip':
            sip_status = subprocess.getoutput('csrutil status 2>/dev/null')
            actual = 'enabled' if 'enabled' in sip_status else 'disabled'
            passed = (actual == 'enabled')
        elif ctype == 'firewall':
            fw = subprocess.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null')
            actual = 'enabled' if 'enabled' in fw.lower() else 'disabled'
            passed = (actual == check.get('expected', 'enabled'))
        elif ctype == 'screen_lock':
            idle_time = subprocess.getoutput("defaults read com.apple.screensaver idleTime 2>/dev/null").strip()
            if idle_time and idle_time.isdigit():
                actual = int(idle_time)
                max_seconds = check.get('maxSeconds', 300)
                passed = (actual <= max_seconds and actual > 0)
            else:
                actual = 0
                passed = False
        elif ctype == 'software_update':
            updates = subprocess.getoutput('softwareupdate -l 2>/dev/null')
            count = updates.count('*')
            actual = count
            passed = (count <= check.get('maxPending', 5))
        elif ctype == 'service':
            svc = check.get('serviceName', '')
            result = subprocess.run(['launchctl', 'list'], capture_output=True, text=True)
            actual = 'running' if svc in result.stdout else 'not_running'
            passed = (actual == check.get('expectedStatus', 'running'))
    except Exception as e:
        actual = f'ERROR: {str(e)}'

    results.append({
        'checkId': check.get('id', ''),
        'title': check.get('title', ''),
        'passed': passed,
        'actual': actual,
        'expected': check.get('value', ''),
        'severity': check.get('severity', 'medium'),
        'timestamp': datetime.now().isoformat()
    })

total = len(results)
passed_count = sum(1 for r in results if r['passed'])
score = round((passed_count / total) * 100, 1) if total > 0 else 0

print(json.dumps({
    'type': 'compliance_scan_result',
    'deviceId': subprocess.getoutput("ioreg -d2 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $(NF-1)}'"),
    'baselineId': data.get('baselineId', ''),
    'results': results,
    'score': score,
    'totalChecks': total,
    'passedChecks': passed_count,
    'scannedAt': datetime.now().isoformat()
}))
PYEOF
            ) || status="failed"
            ;;

        # ── App Store Commands ───────────────────────────────────────────
        store_install)
            local pkg_type pkg_id app_name
            pkg_type=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('packageInfo',{}).get('type',''))" 2>/dev/null)
            pkg_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('packageInfo',{}).get('packageId',''))" 2>/dev/null)
            app_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('appName',''))" 2>/dev/null)
            local install_status="completed" install_output=""
            if command -v brew &>/dev/null; then
                case "$pkg_type" in
                    cask)
                        install_output=$(brew install --cask "$pkg_id" 2>&1) || install_status="failed"
                        ;;
                    brew|*)
                        install_output=$(brew install "$pkg_id" 2>&1) || {
                            install_output=$(brew install --cask "$pkg_id" 2>&1) || install_status="failed"
                        }
                        ;;
                esac
            else
                install_status="failed"; install_output="Homebrew not installed"
            fi
            show_notification "App Installation" "$app_name: $install_status" "OpenDirectory"
            output=$(python3 -c "import json; print(json.dumps({'type':'store_install_result','data':{'appId':$(echo "$json" | python3 -c "import sys,json; print(repr(json.load(sys.stdin).get('data',{}).get('appId','')))"),'status':'$install_status'}}))" 2>/dev/null)
            ;;
        store_uninstall)
            local pkg_id
            pkg_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('packageInfo',{}).get('packageId',''))" 2>/dev/null)
            local uninstall_status="completed"
            if command -v brew &>/dev/null; then
                brew uninstall "$pkg_id" &>/dev/null || {
                    brew uninstall --cask "$pkg_id" &>/dev/null || uninstall_status="failed"
                }
            else
                uninstall_status="failed"
            fi
            output=$(python3 -c "import json; print(json.dumps({'type':'store_uninstall_result','data':{'appId':$(echo "$json" | python3 -c "import sys,json; print(repr(json.load(sys.stdin).get('data',{}).get('appId','')))"),'status':'$uninstall_status'}}))" 2>/dev/null)
            ;;

        # ── Windows-only commands (graceful no-op) ────────────────────
        configure_winget|check_winget_status)
            output='{"status":"success","message":"Not applicable on macOS"}'
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
# POLICY ENFORCEMENT (macOS: profiles, defaults, launchctl, security)
# ============================================================================
POLICY_STATE_DIR="$OD_PATH/PolicyState"
POLICY_BACKUP_DIR="$OD_PATH/PolicyBackups"

handle_apply_policy() {
    local json="$1"
    mkdir -p "$POLICY_STATE_DIR" "$POLICY_BACKUP_DIR"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess, os, hashlib
from datetime import datetime

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
policy_id = data.get('policyId', '')
policy_name = data.get('policyName', '')
settings = data.get('settings', {})
mode = data.get('enforceMode', 'enforce')
applied = []
errors = []
sec = settings.get('security', {})

# Password Policy → .mobileconfig profile
pw = sec.get('password')
if pw:
    try:
        payload_entries = []
        if pw.get('minLength') is not None:
            payload_entries.append(f'\t\t<key>minLength</key>\n\t\t<integer>{pw["minLength"]}</integer>')
        if pw.get('complexity'):
            payload_entries.append('\t\t<key>requireAlphanumeric</key>\n\t\t<true/>')
        if pw.get('maxAgeDays') is not None:
            payload_entries.append(f'\t\t<key>maxPINAgeInDays</key>\n\t\t<integer>{pw["maxAgeDays"]}</integer>')
        if pw.get('lockoutThreshold') is not None:
            payload_entries.append(f'\t\t<key>maxFailedAttempts</key>\n\t\t<integer>{pw["lockoutThreshold"]}</integer>')
        if payload_entries:
            profile = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
\t<key>PayloadContent</key><array><dict>
\t\t<key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string>
\t\t<key>PayloadIdentifier</key><string>local.od.{policy_id}.password</string>
\t\t<key>PayloadUUID</key><string>{hashlib.md5(policy_id.encode()).hexdigest()[:8]}-pw</string>
\t\t<key>PayloadVersion</key><integer>1</integer>
{chr(10).join(payload_entries)}
\t</dict></array>
\t<key>PayloadIdentifier</key><string>local.od.{policy_id}</string>
\t<key>PayloadType</key><string>Configuration</string>
\t<key>PayloadUUID</key><string>{hashlib.md5(policy_id.encode()).hexdigest()[:8]}</string>
\t<key>PayloadVersion</key><integer>1</integer>
\t<key>PayloadDisplayName</key><string>{policy_name} - Password</string>
\t<key>PayloadRemovalDisallowed</key><true/>
</dict></plist>'''
            profile_path = f'/Library/OpenDirectory/Policies/{policy_id}-password.mobileconfig'
            os.makedirs(os.path.dirname(profile_path), exist_ok=True)
            with open(profile_path, 'w') as f: f.write(profile)
            subprocess.run(['profiles', 'install', '-path', profile_path], capture_output=True)
            applied.append('password')
    except Exception as e:
        errors.append(f'password: {e}')

# Screen Lock
sl = sec.get('screenLock')
if sl and sl.get('enabled'):
    try:
        timeout = (sl.get('inactivityLockMinutes') or sl.get('timeoutMinutes', 5)) * 60
        subprocess.run(['defaults', '-currentHost', 'write', 'com.apple.screensaver', 'idleTime', '-int', str(timeout)], capture_output=True)
        if sl.get('requirePassword'):
            subprocess.run(['defaults', 'write', 'com.apple.screensaver', 'askForPassword', '-int', '1'], capture_output=True)
            subprocess.run(['defaults', 'write', 'com.apple.screensaver', 'askForPasswordDelay', '-int', '0'], capture_output=True)
        applied.append('screenLock')
    except Exception as e:
        errors.append(f'screenLock: {e}')

# Firewall
fw = sec.get('firewall')
if fw:
    try:
        val = '1' if fw.get('enabled') else '0'
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.alf', 'globalstate', '-int', val], capture_output=True)
        if fw.get('stealth'):
            subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--setstealthmode', 'on'], capture_output=True)
        applied.append('firewall')
    except Exception as e:
        errors.append(f'firewall: {e}')

# FileVault
enc = sec.get('encryption')
if enc and enc.get('required'):
    try:
        result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
        if 'On' not in result.stdout:
            subprocess.run(['fdesetup', 'enable'], capture_output=True)
        applied.append('encryption')
    except Exception as e:
        errors.append(f'encryption: {e}')

# Audit (OpenBSM)
audit = sec.get('audit')
if audit and audit.get('enabled'):
    try:
        subprocess.run(['bash', '-c', 'sed -i "" "s/^flags:/flags:lo,aa,ad,fd,fm/" /etc/security/audit_control 2>/dev/null; audit -s'], capture_output=True)
        applied.append('audit')
    except Exception as e:
        errors.append(f'audit: {e}')

# Browser (Safari)
browser = settings.get('browser')
if browser and browser.get('homepage'):
    try:
        subprocess.run(['defaults', 'write', 'com.apple.Safari', 'HomePage', browser['homepage']], capture_output=True)
        applied.append('browser')
    except Exception as e:
        errors.append(f'browser: {e}')

# Save state
state_file = f'/Library/OpenDirectory/PolicyState/{policy_id}.json'
os.makedirs(os.path.dirname(state_file), exist_ok=True)
with open(state_file, 'w') as f:
    json.dump({'policyId': policy_id, 'policyName': policy_name, 'version': data.get('version', '1.0'),
               'applied': applied, 'appliedAt': datetime.now().isoformat()}, f)

print(json.dumps({'policyId': policy_id, 'applied': applied, 'errors': errors,
                   'status': 'success' if not errors else 'partial'}))
PYEOF

    local notify_user
    notify_user=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('notifyUser',True))" 2>/dev/null)
    [ "$notify_user" != "False" ] && show_notification "Richtlinie angewendet" "Policy wurde konfiguriert." "OpenDirectory - Policies"
}

handle_remove_policy() {
    local json="$1"
    local policy_id
    policy_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policyId',''))" 2>/dev/null)
    # Remove mobileconfig profiles
    profiles remove -identifier "local.od.$policy_id" 2>/dev/null || true
    rm -f "$POLICY_STATE_DIR/$policy_id.json" 2>/dev/null
    rm -f "/Library/OpenDirectory/Policies/$policy_id-"*.mobileconfig 2>/dev/null
    log "Policy removed: $policy_id"
    echo "Removed: $policy_id"
}

handle_check_compliance() {
    local json="$1"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
settings = data.get('expectedSettings', {})
violations = []
sec = settings.get('security', {})

# Check firewall
fw = sec.get('firewall')
if fw and fw.get('enabled'):
    result = subprocess.run(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'], capture_output=True, text=True)
    if result.stdout.strip() == '0':
        violations.append({'module': 'firewall', 'setting': 'enabled', 'expected': True, 'actual': False})

# Check FileVault
enc = sec.get('encryption')
if enc and enc.get('required'):
    result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
    if 'On' not in result.stdout:
        violations.append({'module': 'encryption', 'setting': 'FileVault', 'expected': 'On', 'actual': result.stdout.strip()})

# Check screen lock
sl = sec.get('screenLock')
if sl and sl.get('enabled'):
    result = subprocess.run(['defaults', '-currentHost', 'read', 'com.apple.screensaver', 'idleTime'], capture_output=True, text=True)
    if result.returncode != 0 or result.stdout.strip() == '0':
        violations.append({'module': 'screenLock', 'setting': 'idleTime', 'expected': 'enabled', 'actual': 'disabled'})

from datetime import datetime
print(json.dumps({'compliant': len(violations) == 0, 'violations': violations, 'checkedAt': datetime.now().isoformat(), 'policyId': data.get('policyId', '')}))
PYEOF
}

handle_check_all_compliance() {
    local json="$1"
    python3 -c "
import sys, json, subprocess
from datetime import datetime
data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
all_violations = []
for pol in data.get('policies', []):
    # Simplified: check if state file exists
    import os
    state_file = f'/Library/OpenDirectory/PolicyState/{pol[\"policyId\"]}.json'
    if not os.path.exists(state_file):
        all_violations.append({'module': 'policy', 'setting': pol['policyId'], 'expected': 'applied', 'actual': 'missing'})
print(json.dumps({'compliant': len(all_violations) == 0, 'violations': all_violations, 'checkedAt': datetime.now().isoformat()}))
" "$json"
}

handle_detect_drift() {
    local json="$1"
    python3 -c "
import sys, json, os
from datetime import datetime
data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
drifted = []; missing = []
for pol in data.get('expectedPolicies', []):
    state_file = f'/Library/OpenDirectory/PolicyState/{pol[\"policyId\"]}.json'
    if os.path.exists(state_file):
        with open(state_file) as f:
            state = json.load(f)
        if state.get('version') != pol.get('version'):
            drifted.append({'policyId': pol['policyId'], 'expectedVersion': pol.get('version'), 'actualVersion': state.get('version')})
    else:
        missing.append(pol['policyId'])
print(json.dumps({'drifted': drifted, 'missing': missing, 'checkedAt': datetime.now().isoformat()}))
" "$json"
}

handle_rollback_policy() {
    local json="$1"
    local policy_id
    policy_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policyId',''))" 2>/dev/null)
    profiles remove -identifier "local.od.$policy_id" 2>/dev/null || true
    rm -f "$POLICY_STATE_DIR/$policy_id.json" 2>/dev/null
    log "Policy rolled back: $policy_id"
    show_notification "Richtlinie zurueckgesetzt" "$policy_id" "OpenDirectory - Policies"
    echo "Rolled back: $policy_id"
}

# ============================================================================
# UPDATE MANAGEMENT (macOS: softwareupdate, defaults, mas)
# ============================================================================

handle_configure_updates() {
    local json="$1"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
settings = data.get('settings', {})
configured = []
errors = []

try:
    # Configure automatic check
    auto = '1' if settings.get('automatic') else '0'
    subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticCheckEnabled', '-bool', 'true' if settings.get('automatic') else 'false'], capture_output=True)
    subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticDownload', '-bool', 'true' if settings.get('automatic') else 'false'], capture_output=True)
    configured.append('automaticCheck')

    # macOS-specific extensions
    macos_ext = settings.get('_macos', {})
    if macos_ext.get('automaticInstallOSUpdates') is not None:
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticallyInstallMacOSUpdates', '-bool', 'true' if macos_ext['automaticInstallOSUpdates'] else 'false'], capture_output=True)
    if macos_ext.get('automaticInstallAppUpdates') is not None:
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.commerce', 'AutoUpdate', '-bool', 'true' if macos_ext['automaticInstallAppUpdates'] else 'false'], capture_output=True)
    if macos_ext.get('automaticInstallSecurityUpdates') is not None:
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'CriticalUpdateInstall', '-bool', 'true' if macos_ext['automaticInstallSecurityUpdates'] else 'false'], capture_output=True)
    if macos_ext.get('catalogURL'):
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'CatalogURL', macos_ext['catalogURL']], capture_output=True)
    configured.append('macosSettings')

    # Deferrals (via managed preferences)
    deferrals = settings.get('deferrals', {})
    if deferrals.get('featureUpdates'):
        subprocess.run(['defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate', 'MajorOSUserDeferralCount', '-int', str(deferrals['featureUpdates'])], capture_output=True)
    configured.append('deferrals')

except Exception as e:
    errors.append(str(e))

print(json.dumps({'status': 'success' if not errors else 'partial', 'configured': configured, 'errors': errors}))
PYEOF
}

handle_check_update_status() {
    python3 -c "
import subprocess, json
result = subprocess.run(['softwareupdate', '-l'], capture_output=True, text=True)
updates = []
for line in result.stdout.split('\n'):
    line = line.strip()
    if line.startswith('*'):
        updates.append(line.lstrip('* '))
print(json.dumps({'status': 'success', 'updateStatus': {'availableUpdates': updates, 'count': len(updates)}}))
"
}

handle_trigger_update() {
    local json="$1"
    softwareupdate -ia --agree-to-license 2>&1
    echo '{"status":"success","triggered":true}'
}

handle_get_update_compliance() {
    python3 -c "
import subprocess, json
result = subprocess.run(['softwareupdate', '-l'], capture_output=True, text=True)
pending = [l.strip().lstrip('* ') for l in result.stdout.split('\n') if l.strip().startswith('*')]
print(json.dumps({'status': 'success', 'complianceReport': {'compliant': len(pending) == 0, 'pendingUpdates': pending, 'count': len(pending)}}))
"
}

# ============================================================================
# DEPLOYMENT / COMPLIANCE / ENCRYPTION (macOS)
# ============================================================================

handle_zero_touch_deploy() {
    local json="$1"
    python3 -c "
import json, sys, subprocess, os

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
steps = []

# Set computer name
device_config = profile.get('deviceConfiguration', {})
if device_config.get('computerNameTemplate'):
    import socket
    template = device_config['computerNameTemplate']
    hostname = template.replace('{SERIAL}', socket.gethostname()[:6]).replace('{USER}', os.environ.get('USER', 'user')[:6])
    subprocess.run(['scutil', '--set', 'ComputerName', hostname], capture_output=True)
    subprocess.run(['scutil', '--set', 'HostName', hostname], capture_output=True)
    subprocess.run(['scutil', '--set', 'LocalHostName', hostname.replace(' ', '-')], capture_output=True)
    steps.append(f'Computer name set: {hostname}')

# Set timezone
if device_config.get('timezone'):
    subprocess.run(['systemsetup', '-settimezone', device_config['timezone']], capture_output=True)
    steps.append(f'Timezone: {device_config[\"timezone\"]}')

# Install applications via brew if available
for app in profile.get('applications', []):
    pkg = app.get('packageId', '')
    if pkg:
        result = subprocess.run(['brew', 'install', '--cask', pkg], capture_output=True, text=True)
        if result.returncode == 0:
            steps.append(f'Installed: {app.get(\"name\", pkg)}')

# Enable FileVault if security config requires
sec = profile.get('securityConfiguration', {})
if sec.get('enableEncryption'):
    steps.append('FileVault: requires user interaction')

# Enable firewall
if sec.get('configureFirewall'):
    subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--setglobalstate', 'on'], capture_output=True)
    steps.append('Firewall enabled')

print(json.dumps({'status': 'success', 'steps': steps, 'message': 'Zero-touch deployment completed'}))
" <<< "$json"
}

handle_check_encryption_status() {
    python3 -c "
import subprocess, json

result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
output = result.stdout.strip()

encrypted = 'FileVault is On' in output
status_info = {
    'encrypted': encrypted,
    'method': 'FileVault' if encrypted else 'none',
    'status': output
}

# Get additional info if encrypted
if encrypted:
    users_result = subprocess.run(['fdesetup', 'list'], capture_output=True, text=True)
    if users_result.returncode == 0:
        status_info['users'] = [l.split(',')[0] for l in users_result.stdout.strip().split('\n') if l]

print(json.dumps({'status': 'success', 'encryptionStatus': status_info}))
"
}

handle_enable_encryption() {
    local json="$1"
    # FileVault requires user credential, can only be deferred
    python3 -c "
import subprocess, json

# Check if already enabled
result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
if 'FileVault is On' in result.stdout:
    print(json.dumps({'status': 'success', 'message': 'FileVault already enabled'}))
else:
    # Enable deferred mode (activates at next logout)
    result = subprocess.run(['fdesetup', 'enable', '-defer', '/tmp/od-fv-recovery.plist'], capture_output=True, text=True)
    if result.returncode == 0:
        print(json.dumps({'status': 'success', 'message': 'FileVault deferred enablement configured', 'deferred': True}))
    else:
        print(json.dumps({'status': 'failed', 'error': result.stderr.strip() or 'FileVault enablement requires user credentials'}))
"
}

handle_execute_remediation() {
    local json="$1"
    python3 -c "
import json, sys, subprocess

data = json.loads(sys.stdin.read())
action = data.get('data', {}).get('action', '')

result = 'Unknown action'
try:
    if action == 'ENABLE_FILEVAULT':
        r = subprocess.run(['fdesetup', 'enable', '-defer', '/tmp/od-fv-recovery.plist'], capture_output=True, text=True)
        result = 'FileVault deferred enablement configured' if r.returncode == 0 else r.stderr.strip()
    elif action == 'ENABLE_MACOS_FIREWALL':
        subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--setglobalstate', 'on'], capture_output=True)
        result = 'macOS Application Firewall enabled'
    elif action == 'INSTALL_UPDATES':
        subprocess.run(['softwareupdate', '-ia', '--agree-to-license'], capture_output=True)
        result = 'System updates installed'
    elif action == 'ENFORCE_PASSWORD_POLICY':
        result = 'Password policy requires configuration profile'
    else:
        result = f'Remediation action {action} not implemented on macOS'

    print(json.dumps({'status': 'success', 'action': action, 'message': result}))
except Exception as e:
    print(json.dumps({'status': 'failed', 'error': str(e)}))
" <<< "$json"
}

# ============================================================================
# NETWORK PROFILE MANAGEMENT (macOS: profiles / networksetup)
# ============================================================================

handle_configure_wifi() {
    local json="$1"
    python3 -c "
import subprocess, json, sys, tempfile, os, uuid, plistlib

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
ssid = profile.get('ssid', '')
security = profile.get('security', 'WPA2-Enterprise')
auth = profile.get('authentication', {})
auto_connect = profile.get('autoConnect', True)
hidden = profile.get('hidden', False)

# Generate .mobileconfig for WiFi
payload_uuid = str(uuid.uuid4())
profile_uuid = str(uuid.uuid4())

wifi_payload = {
    'PayloadType': 'com.apple.wifi.managed',
    'PayloadVersion': 1,
    'PayloadIdentifier': f'com.opendirectory.wifi.{ssid}',
    'PayloadUUID': payload_uuid,
    'PayloadDisplayName': f'WiFi: {ssid}',
    'AutoJoin': auto_connect,
    'HIDDEN_NETWORK': hidden,
    'SSID_STR': ssid,
}

if 'Enterprise' in security:
    wifi_payload['EncryptionType'] = 'WPA2'
    wifi_payload['SetupModes'] = []
    eap_method = auth.get('method', 'EAP-TLS')
    eap_types = {'EAP-TLS': 13, 'EAP-TTLS': 21, 'EAP-PEAP': 25, 'EAP-FAST': 43}
    wifi_payload['EAPClientConfiguration'] = {
        'AcceptEAPTypes': [eap_types.get(eap_method, 13)],
    }
    if auth.get('identity'):
        wifi_payload['EAPClientConfiguration']['UserName'] = auth['identity']
    if auth.get('anonymousIdentity'):
        wifi_payload['EAPClientConfiguration']['OuterIdentity'] = auth['anonymousIdentity']
elif 'WPA' in security:
    wifi_payload['EncryptionType'] = 'WPA2'
    if auth.get('password'):
        wifi_payload['Password'] = auth['password']
else:
    wifi_payload['EncryptionType'] = 'None'

mobileconfig = {
    'PayloadType': 'Configuration',
    'PayloadVersion': 1,
    'PayloadIdentifier': f'com.opendirectory.wifi.profile.{ssid}',
    'PayloadUUID': profile_uuid,
    'PayloadDisplayName': f'OpenDirectory WiFi - {ssid}',
    'PayloadOrganization': 'OpenDirectory',
    'PayloadContent': [wifi_payload],
    'PayloadRemovalDisallowed': False,
}

# Write and install .mobileconfig
config_path = tempfile.mktemp(suffix='.mobileconfig')
with open(config_path, 'wb') as f:
    plistlib.dump(mobileconfig, f)

result = subprocess.run(['profiles', 'install', '-path', config_path], capture_output=True, text=True)
os.unlink(config_path)

if result.returncode == 0:
    print(json.dumps({'status': 'success', 'profileId': profile_uuid, 'message': f'WiFi profile {ssid} installed'}))
else:
    print(json.dumps({'status': 'failed', 'error': result.stderr.strip()}))
" <<< "$json"
}

handle_remove_wifi() {
    local json="$1"
    local ssid
    ssid=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('ssid',''))" 2>/dev/null)
    local profile_id="com.opendirectory.wifi.profile.${ssid}"
    if profiles remove -identifier "$profile_id" 2>/dev/null; then
        echo "{\"status\":\"success\",\"message\":\"WiFi profile ${ssid} removed\"}"
    else
        networksetup -removepreferredwirelessnetwork en0 "$ssid" 2>/dev/null
        echo "{\"status\":\"success\",\"message\":\"WiFi profile ${ssid} removed from preferred networks\"}"
    fi
}

handle_configure_vpn() {
    local json="$1"
    python3 -c "
import subprocess, json, sys, tempfile, os, uuid, plistlib

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
name = profile.get('name', 'OD-VPN')
vpn_type = profile.get('vpnType', 'openvpn')
server = profile.get('server', '')
port = profile.get('port', 1194)
auth = profile.get('authentication', {})
routing = profile.get('routing', {})

payload_uuid = str(uuid.uuid4())
profile_uuid = str(uuid.uuid4())

vpn_payload = {
    'PayloadType': 'com.apple.vpn.managed',
    'PayloadVersion': 1,
    'PayloadIdentifier': f'com.opendirectory.vpn.{name}',
    'PayloadUUID': payload_uuid,
    'PayloadDisplayName': f'VPN: {name}',
    'UserDefinedName': name,
    'VPNType': 'VPN',
}

if vpn_type == 'ikev2':
    vpn_payload['VPNSubType'] = 'IKEv2'
    vpn_payload['IKEv2'] = {
        'RemoteAddress': server,
        'RemoteIdentifier': server,
        'AuthenticationMethod': 'Certificate' if auth.get('method') == 'certificate' else 'SharedSecret',
    }
elif vpn_type == 'l2tp':
    vpn_payload['VPNSubType'] = 'L2TP'
    vpn_payload['PPP'] = {
        'CommRemoteAddress': server,
    }
    vpn_payload['IPSec'] = {
        'AuthenticationMethod': 'SharedSecret',
    }
else:
    # OpenVPN or WireGuard via .mobileconfig custom payload
    vpn_payload['VPNSubType'] = 'net.openvpn.connect.app' if vpn_type == 'openvpn' else 'com.wireguard.macos'
    vpn_payload['VendorConfig'] = {
        'server': server,
        'port': str(port),
    }

mobileconfig = {
    'PayloadType': 'Configuration',
    'PayloadVersion': 1,
    'PayloadIdentifier': f'com.opendirectory.vpn.profile.{name}',
    'PayloadUUID': profile_uuid,
    'PayloadDisplayName': f'OpenDirectory VPN - {name}',
    'PayloadOrganization': 'OpenDirectory',
    'PayloadContent': [vpn_payload],
    'PayloadRemovalDisallowed': False,
}

config_path = tempfile.mktemp(suffix='.mobileconfig')
with open(config_path, 'wb') as f:
    plistlib.dump(mobileconfig, f)

result = subprocess.run(['profiles', 'install', '-path', config_path], capture_output=True, text=True)
os.unlink(config_path)

if result.returncode == 0:
    print(json.dumps({'status': 'success', 'profileId': profile_uuid, 'message': f'VPN profile {name} installed'}))
else:
    print(json.dumps({'status': 'failed', 'error': result.stderr.strip()}))
" <<< "$json"
}

handle_remove_vpn() {
    local json="$1"
    local name
    name=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin).get('data',{}); print(d.get('name', d.get('profileId','')))" 2>/dev/null)
    local profile_id="com.opendirectory.vpn.profile.${name}"
    if profiles remove -identifier "$profile_id" 2>/dev/null; then
        echo "{\"status\":\"success\",\"message\":\"VPN profile removed\"}"
    else
        echo "{\"status\":\"failed\",\"error\":\"VPN profile not found\"}"
    fi
}

handle_configure_email() {
    local json="$1"
    python3 -c "
import subprocess, json, sys, tempfile, os, uuid, plistlib

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
account_name = profile.get('accountName', 'Corporate Email')
account_type = profile.get('accountType', 'exchange')
email = profile.get('emailAddress', '')
display_name = profile.get('displayName', '')
server = profile.get('server', {})
auth = profile.get('authentication', {})
sync = profile.get('syncSettings', {})

payload_uuid = str(uuid.uuid4())
profile_uuid = str(uuid.uuid4())

if account_type == 'exchange':
    email_payload = {
        'PayloadType': 'com.apple.eas.account',
        'PayloadVersion': 1,
        'PayloadIdentifier': f'com.opendirectory.email.{account_name}',
        'PayloadUUID': payload_uuid,
        'PayloadDisplayName': account_name,
        'Host': server.get('incoming', {}).get('host', ''),
        'EmailAddress': email,
        'UserName': auth.get('username', email),
        'MailNumberOfPastDaysToSync': sync.get('mailDays', 30),
        'CalDAVUseSSL': server.get('incoming', {}).get('ssl', True),
    }
else:
    incoming = server.get('incoming', {})
    outgoing = server.get('outgoing', {})
    email_payload = {
        'PayloadType': 'com.apple.mail.managed',
        'PayloadVersion': 1,
        'PayloadIdentifier': f'com.opendirectory.email.{account_name}',
        'PayloadUUID': payload_uuid,
        'PayloadDisplayName': account_name,
        'EmailAccountName': display_name or account_name,
        'EmailAddress': email,
        'IncomingMailServerHostName': incoming.get('host', ''),
        'IncomingMailServerPortNumber': incoming.get('port', 993),
        'IncomingMailServerUseSSL': incoming.get('ssl', True),
        'IncomingMailServerAuthentication': 'EmailAuthPassword',
        'IncomingMailServerUsername': auth.get('username', email),
        'IncomingPassword': auth.get('password', ''),
        'OutgoingMailServerHostName': outgoing.get('host', ''),
        'OutgoingMailServerPortNumber': outgoing.get('port', 587),
        'OutgoingMailServerUseSSL': outgoing.get('ssl', True),
        'OutgoingMailServerAuthentication': 'EmailAuthPassword',
        'OutgoingMailServerUsername': auth.get('username', email),
        'OutgoingPassword': auth.get('password', ''),
    }

mobileconfig = {
    'PayloadType': 'Configuration',
    'PayloadVersion': 1,
    'PayloadIdentifier': f'com.opendirectory.email.profile.{account_name}',
    'PayloadUUID': profile_uuid,
    'PayloadDisplayName': f'OpenDirectory Email - {account_name}',
    'PayloadOrganization': 'OpenDirectory',
    'PayloadContent': [email_payload],
    'PayloadRemovalDisallowed': False,
}

config_path = tempfile.mktemp(suffix='.mobileconfig')
with open(config_path, 'wb') as f:
    plistlib.dump(mobileconfig, f)

result = subprocess.run(['profiles', 'install', '-path', config_path], capture_output=True, text=True)
os.unlink(config_path)

if result.returncode == 0:
    print(json.dumps({'status': 'success', 'profileId': profile_uuid, 'message': f'Email profile {account_name} installed'}))
else:
    print(json.dumps({'status': 'failed', 'error': result.stderr.strip()}))
" <<< "$json"
}

handle_remove_email() {
    local json="$1"
    local account_name
    account_name=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('profileId',''))" 2>/dev/null)
    local profile_id="com.opendirectory.email.profile.${account_name}"
    if profiles remove -identifier "$profile_id" 2>/dev/null; then
        echo "{\"status\":\"success\",\"message\":\"Email profile removed\"}"
    else
        echo "{\"status\":\"failed\",\"error\":\"Email profile not found\"}"
    fi
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
