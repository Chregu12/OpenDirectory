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
            output=$(handle_apply_policy "$json") || status="failed"
            ;;
        apply_policy_module)
            output=$(handle_apply_policy "$json") || status="failed"
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

        # ── Printer Commands (Linux: lpadmin / CUPS) ──────────────────
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
            pname=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('printerName',''))" 2>/dev/null)
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
# POLICY ENFORCEMENT (Linux: sysctl, PAM, sshd, ufw/firewalld, auditd, dconf)
# ============================================================================
POLICY_STATE_DIR="$OD_PATH/PolicyState"
POLICY_BACKUP_DIR="$OD_PATH/PolicyBackups"

handle_apply_policy() {
    local json="$1"
    mkdir -p "$POLICY_STATE_DIR" "$POLICY_BACKUP_DIR"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess, os, shutil
from datetime import datetime

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
policy_id = data.get('policyId', '')
policy_name = data.get('policyName', '')
settings = data.get('settings', {})
applied = []
errors = []
sec = settings.get('security', {})

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Password Policy → PAM pwquality + faillock
pw = sec.get('password')
if pw:
    try:
        if os.path.exists('/etc/security/pwquality.conf'):
            lines = []
            if pw.get('minLength') is not None:
                lines.append(f'minlen = {pw["minLength"]}')
            if pw.get('complexity'):
                lines.extend(['dcredit = -1', 'ucredit = -1', 'lcredit = -1', 'ocredit = -1'])
            if lines:
                with open('/etc/security/pwquality.conf', 'a') as f:
                    f.write('\n# OpenDirectory Policy\n' + '\n'.join(lines) + '\n')
        if pw.get('maxAgeDays') is not None:
            run(f'sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t{pw["maxAgeDays"]}/" /etc/login.defs')
        if pw.get('lockoutThreshold') is not None:
            with open('/etc/security/faillock.conf', 'a') as f:
                f.write(f'\n# OpenDirectory Policy\ndeny = {pw["lockoutThreshold"]}\n')
            if pw.get('lockoutDuration') is not None:
                with open('/etc/security/faillock.conf', 'a') as f:
                    f.write(f'unlock_time = {pw["lockoutDuration"] * 60}\n')
        applied.append('password')
    except Exception as e:
        errors.append(f'password: {e}')

# Screen Lock → dconf (GNOME) / xdg-screensaver
sl = sec.get('screenLock')
if sl and sl.get('enabled'):
    try:
        timeout = (sl.get('inactivityLockMinutes') or sl.get('timeoutMinutes', 5)) * 60
        dconf_dir = '/etc/dconf/db/local.d'
        os.makedirs(dconf_dir, exist_ok=True)
        with open(f'{dconf_dir}/00-od-screenlock', 'w') as f:
            f.write(f'[org/gnome/desktop/session]\nidle-delay=uint32 {timeout}\n')
            if sl.get('requirePassword'):
                f.write('[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 0\n')
        run('dconf update')
        applied.append('screenLock')
    except Exception as e:
        errors.append(f'screenLock: {e}')

# Firewall → ufw or firewalld
fw = sec.get('firewall')
if fw:
    try:
        if os.path.exists('/usr/sbin/ufw'):
            if fw.get('enabled'):
                run('ufw --force enable')
                if fw.get('defaultDeny'):
                    run('ufw default deny incoming')
            else:
                run('ufw --force disable')
        elif os.path.exists('/usr/bin/firewall-cmd'):
            if fw.get('enabled'):
                run('systemctl enable --now firewalld')
                if fw.get('defaultDeny'):
                    run('firewall-cmd --set-default-zone=drop')
            else:
                run('systemctl disable --now firewalld')
        applied.append('firewall')
    except Exception as e:
        errors.append(f'firewall: {e}')

# Encryption → LUKS check (report only, no in-place enable)
enc = sec.get('encryption')
if enc and enc.get('required'):
    try:
        result = run('lsblk -o NAME,FSTYPE | grep -i crypt')
        if result.returncode != 0:
            errors.append('encryption: LUKS not detected on root device')
        else:
            applied.append('encryption')
    except Exception as e:
        errors.append(f'encryption: {e}')

# Audit → auditd rules
audit = sec.get('audit')
if audit and audit.get('enabled'):
    try:
        run('systemctl enable --now auditd')
        rules_file = '/etc/audit/rules.d/od-policy.rules'
        with open(rules_file, 'w') as f:
            f.write('# OpenDirectory Audit Policy\n')
            f.write('-w /etc/passwd -p wa -k identity\n')
            f.write('-w /etc/shadow -p wa -k identity\n')
            f.write('-w /etc/group -p wa -k identity\n')
            f.write('-w /var/log/auth.log -p wa -k auth-log\n')
            f.write('-a always,exit -F arch=b64 -S execve -k exec\n')
        run('augenrules --load')
        applied.append('audit')
    except Exception as e:
        errors.append(f'audit: {e}')

# SSH hardening
ssh = sec.get('ssh') or sec.get('remoteAccess')
if ssh:
    try:
        sshd_conf = '/etc/ssh/sshd_config.d/od-policy.conf'
        os.makedirs(os.path.dirname(sshd_conf), exist_ok=True)
        lines = ['# OpenDirectory Policy']
        if ssh.get('disableRoot'):
            lines.append('PermitRootLogin no')
        if ssh.get('requireKey'):
            lines.append('PasswordAuthentication no')
            lines.append('PubkeyAuthentication yes')
        if ssh.get('maxAuthTries') is not None:
            lines.append(f'MaxAuthTries {ssh["maxAuthTries"]}')
        with open(sshd_conf, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        run('systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null')
        applied.append('ssh')
    except Exception as e:
        errors.append(f'ssh: {e}')

# Browser (Chrome/Chromium policies)
browser = settings.get('browser')
if browser and browser.get('homepage'):
    try:
        policy_dir = '/etc/opt/chrome/policies/managed'
        os.makedirs(policy_dir, exist_ok=True)
        chrome_pol = {}
        if browser.get('homepage'):
            chrome_pol['HomepageLocation'] = browser['homepage']
            chrome_pol['HomepageIsNewTabPage'] = False
        if browser.get('defaultSearchEngine'):
            chrome_pol['DefaultSearchProviderName'] = browser['defaultSearchEngine']
        with open(f'{policy_dir}/od-policy.json', 'w') as f:
            json.dump(chrome_pol, f, indent=2)
        # Also for Chromium
        chromium_dir = '/etc/chromium/policies/managed'
        os.makedirs(chromium_dir, exist_ok=True)
        shutil.copy(f'{policy_dir}/od-policy.json', f'{chromium_dir}/od-policy.json')
        applied.append('browser')
    except Exception as e:
        errors.append(f'browser: {e}')

# Updates
updates = settings.get('updates')
if updates:
    try:
        if os.path.exists('/usr/bin/apt-get'):
            apt_conf = '/etc/apt/apt.conf.d/50-od-autoupdate'
            enabled = '1' if updates.get('automatic') else '0'
            with open(apt_conf, 'w') as f:
                f.write(f'APT::Periodic::Update-Package-Lists "{enabled}";\n')
                f.write(f'APT::Periodic::Unattended-Upgrade "{enabled}";\n')
        applied.append('updates')
    except Exception as e:
        errors.append(f'updates: {e}')

# Save state
state_file = f'/opt/opendirectory/PolicyState/{policy_id}.json'
os.makedirs(os.path.dirname(state_file), exist_ok=True)
with open(state_file, 'w') as f:
    json.dump({'policyId': policy_id, 'policyName': policy_name, 'version': data.get('version', '1.0'),
               'applied': applied, 'appliedAt': datetime.now().isoformat()}, f)

print(json.dumps({'policyId': policy_id, 'applied': applied, 'errors': errors,
                   'status': 'success' if not errors else 'partial'}))
PYEOF

    local notify_user
    notify_user=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('notifyUser',True))" 2>/dev/null)
    [ "$notify_user" != "False" ] && show_notification "Richtlinie angewendet" "Policy wurde konfiguriert."
}

handle_remove_policy() {
    local json="$1"
    local policy_id
    policy_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policyId',''))" 2>/dev/null)
    # Remove policy config files
    rm -f "/etc/security/faillock.conf.d/od-$policy_id.conf" 2>/dev/null
    rm -f "/etc/audit/rules.d/od-policy.rules" 2>/dev/null && augenrules --load 2>/dev/null
    rm -f "/etc/ssh/sshd_config.d/od-policy.conf" 2>/dev/null && systemctl reload sshd 2>/dev/null
    rm -f "/etc/dconf/db/local.d/00-od-screenlock" 2>/dev/null && dconf update 2>/dev/null
    rm -f "$POLICY_STATE_DIR/$policy_id.json" 2>/dev/null
    log "Policy removed: $policy_id"
    echo "Removed: $policy_id"
}

handle_check_compliance() {
    local json="$1"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess, os
from datetime import datetime

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
settings = data.get('expectedSettings', {})
violations = []
sec = settings.get('security', {})

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Check firewall
fw = sec.get('firewall')
if fw and fw.get('enabled'):
    ufw_result = run('ufw status')
    fwd_result = run('systemctl is-active firewalld')
    if 'active' not in ufw_result.stdout.lower() and 'active' != fwd_result.stdout.strip():
        violations.append({'module': 'firewall', 'setting': 'enabled', 'expected': True, 'actual': False})

# Check encryption
enc = sec.get('encryption')
if enc and enc.get('required'):
    result = run('lsblk -o NAME,FSTYPE | grep -i crypt')
    if result.returncode != 0:
        violations.append({'module': 'encryption', 'setting': 'LUKS', 'expected': 'encrypted', 'actual': 'unencrypted'})

# Check screen lock (dconf)
sl = sec.get('screenLock')
if sl and sl.get('enabled'):
    if not os.path.exists('/etc/dconf/db/local.d/00-od-screenlock'):
        violations.append({'module': 'screenLock', 'setting': 'dconf', 'expected': 'configured', 'actual': 'missing'})

# Check audit
audit = sec.get('audit')
if audit and audit.get('enabled'):
    result = run('systemctl is-active auditd')
    if result.stdout.strip() != 'active':
        violations.append({'module': 'audit', 'setting': 'auditd', 'expected': 'active', 'actual': result.stdout.strip()})

print(json.dumps({'compliant': len(violations) == 0, 'violations': violations,
                   'checkedAt': datetime.now().isoformat(), 'policyId': data.get('policyId', '')}))
PYEOF
}

handle_check_all_compliance() {
    local json="$1"
    python3 -c "
import sys, json, os
from datetime import datetime
data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
all_violations = []
for pol in data.get('policies', []):
    state_file = f'/opt/opendirectory/PolicyState/{pol[\"policyId\"]}.json'
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
    state_file = f'/opt/opendirectory/PolicyState/{pol[\"policyId\"]}.json'
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
    # Remove policy artifacts
    rm -f "/etc/audit/rules.d/od-policy.rules" 2>/dev/null && augenrules --load 2>/dev/null
    rm -f "/etc/ssh/sshd_config.d/od-policy.conf" 2>/dev/null && systemctl reload sshd 2>/dev/null
    rm -f "/etc/dconf/db/local.d/00-od-screenlock" 2>/dev/null && dconf update 2>/dev/null
    rm -f "$POLICY_STATE_DIR/$policy_id.json" 2>/dev/null
    log "Policy rolled back: $policy_id"
    show_notification "Richtlinie zurueckgesetzt" "$policy_id"
    echo "Rolled back: $policy_id"
}

# ============================================================================
# UPDATE MANAGEMENT (Linux: apt/dnf/snap, unattended-upgrades, systemd timers)
# ============================================================================

handle_configure_updates() {
    local json="$1"
    python3 << 'PYEOF' "$json"
import sys, json, subprocess, os

data = json.loads(sys.argv[1]).get('data', json.loads(sys.argv[1]))
settings = data.get('settings', {})
configured = []
errors = []
linux_ext = settings.get('_linux', {})

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

try:
    # apt-based systems (Debian/Ubuntu)
    if os.path.exists('/usr/bin/apt-get'):
        # Configure unattended-upgrades
        auto = '1' if settings.get('automatic') else '0'
        conf_path = '/etc/apt/apt.conf.d/50-od-autoupdate'
        with open(conf_path, 'w') as f:
            f.write(f'APT::Periodic::Update-Package-Lists "{auto}";\n')
            f.write(f'APT::Periodic::Unattended-Upgrade "{auto}";\n')
            f.write(f'APT::Periodic::AutocleanInterval "7";\n')
            if linux_ext.get('autoRemoveUnused'):
                f.write('Unattended-Upgrade::Remove-Unused-Dependencies "true";\n')
            if linux_ext.get('securityUpdatesOnly'):
                f.write('Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; };\n')
            if linux_ext.get('blockedPackages'):
                for pkg in linux_ext['blockedPackages']:
                    f.write(f'Unattended-Upgrade::Package-Blacklist {{ "{pkg}"; }};\n')
        configured.append('apt-unattended-upgrades')

    # dnf-based systems (RHEL/Fedora)
    elif os.path.exists('/usr/bin/dnf'):
        auto = 'yes' if settings.get('automatic') else 'no'
        conf_path = '/etc/dnf/automatic.conf'
        if os.path.exists(conf_path):
            run(f'sed -i "s/^apply_updates.*/apply_updates = {auto}/" {conf_path}')
            if settings.get('automatic'):
                run('systemctl enable --now dnf-automatic.timer')
            configured.append('dnf-automatic')

    # snap auto-refresh
    pm = linux_ext.get('packageManagers', {})
    if pm.get('snap', {}).get('autoRefresh') is False:
        run('snap set system refresh.hold="$(date -d "+100 years" +%Y-%m-%dT%H:%M:%S+00:00)"')
        configured.append('snap-hold')

except Exception as e:
    errors.append(str(e))

print(json.dumps({'status': 'success' if not errors else 'partial', 'configured': configured, 'errors': errors}))
PYEOF
}

handle_check_update_status() {
    python3 -c "
import subprocess, json, os
updates = []
if os.path.exists('/usr/bin/apt-get'):
    subprocess.run(['apt-get', 'update', '-qq'], capture_output=True)
    result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
    updates = [l.split('/')[0] for l in result.stdout.strip().split('\n')[1:] if '/' in l]
elif os.path.exists('/usr/bin/dnf'):
    result = subprocess.run(['dnf', 'check-update', '-q'], capture_output=True, text=True)
    updates = [l.split()[0] for l in result.stdout.strip().split('\n') if l.strip() and not l.startswith('Last')]
print(json.dumps({'status': 'success', 'updateStatus': {'availableUpdates': updates, 'count': len(updates)}}))
"
}

handle_trigger_update() {
    local json="$1"
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1
    elif command -v dnf &>/dev/null; then
        dnf upgrade -y 2>&1
    fi
    echo '{"status":"success","triggered":true}'
}

handle_get_update_compliance() {
    python3 -c "
import subprocess, json, os
updates = []
if os.path.exists('/usr/bin/apt-get'):
    subprocess.run(['apt-get', 'update', '-qq'], capture_output=True)
    result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
    updates = [l.split('/')[0] for l in result.stdout.strip().split('\n')[1:] if '/' in l]
    security = [u for u in updates if 'security' in subprocess.run(['apt-cache', 'show', u], capture_output=True, text=True).stdout.lower()]
elif os.path.exists('/usr/bin/dnf'):
    result = subprocess.run(['dnf', 'check-update', '-q', '--security'], capture_output=True, text=True)
    updates = [l.split()[0] for l in result.stdout.strip().split('\n') if l.strip()]
print(json.dumps({'status': 'success', 'complianceReport': {'compliant': len(updates) == 0, 'pendingUpdates': updates, 'count': len(updates)}}))
"
}

# ============================================================================
# NETWORK PROFILE MANAGEMENT (Linux: NetworkManager / nmcli)
# ============================================================================

handle_configure_wifi() {
    local json="$1"
    python3 -c "
import subprocess, json, sys

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
ssid = profile.get('ssid', '')
security = profile.get('security', 'WPA2-Enterprise')
auth = profile.get('authentication', {})
certs = profile.get('certificates', {})
auto_connect = profile.get('autoConnect', True)
hidden = profile.get('hidden', False)

conn_name = f'OD-WiFi-{ssid}'

# Remove existing connection with same name
subprocess.run(['nmcli', 'connection', 'delete', conn_name], capture_output=True)

cmd = ['nmcli', 'connection', 'add', 'type', 'wifi', 'con-name', conn_name, 'ssid', ssid]

if hidden:
    cmd += ['wifi.hidden', 'yes']

if 'Enterprise' in security:
    cmd += ['wifi-sec.key-mgmt', 'wpa-eap']
    eap_method = auth.get('method', 'EAP-TLS').replace('EAP-', '').lower()
    cmd += ['802-1x.eap', eap_method]
    if auth.get('identity'):
        cmd += ['802-1x.identity', auth['identity']]
    if auth.get('anonymousIdentity'):
        cmd += ['802-1x.anonymous-identity', auth['anonymousIdentity']]
    if certs.get('ca', {}).get('data'):
        ca_path = f'/etc/NetworkManager/certs/od-wifi-{ssid}-ca.pem'
        subprocess.run(['mkdir', '-p', '/etc/NetworkManager/certs'], capture_output=True)
        with open(ca_path, 'w') as f:
            f.write(certs['ca']['data'])
        cmd += ['802-1x.ca-cert', ca_path]
    if certs.get('client', {}).get('data'):
        client_path = f'/etc/NetworkManager/certs/od-wifi-{ssid}-client.p12'
        with open(client_path, 'wb') as f:
            import base64
            f.write(base64.b64decode(certs['client']['data']))
        cmd += ['802-1x.private-key', client_path]
        if certs['client'].get('password'):
            cmd += ['802-1x.private-key-password', certs['client']['password']]
elif 'WPA' in security:
    cmd += ['wifi-sec.key-mgmt', 'wpa-psk']
    if auth.get('password'):
        cmd += ['wifi-sec.psk', auth['password']]

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    if auto_connect:
        subprocess.run(['nmcli', 'connection', 'modify', conn_name, 'connection.autoconnect', 'yes'], capture_output=True)
    print(json.dumps({'status': 'success', 'profileId': conn_name, 'message': f'WiFi profile {ssid} configured'}))
else:
    print(json.dumps({'status': 'failed', 'error': result.stderr.strip()}))
" <<< "$json"
}

handle_remove_wifi() {
    local json="$1"
    local ssid
    ssid=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('ssid',''))" 2>/dev/null)
    local conn_name="OD-WiFi-${ssid}"
    if nmcli connection delete "$conn_name" 2>/dev/null; then
        echo "{\"status\":\"success\",\"message\":\"WiFi profile ${ssid} removed\"}"
    else
        echo "{\"status\":\"failed\",\"error\":\"WiFi profile ${ssid} not found\"}"
    fi
}

handle_configure_vpn() {
    local json="$1"
    python3 -c "
import subprocess, json, sys, os

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
name = profile.get('name', 'OD-VPN')
vpn_type = profile.get('vpnType', 'openvpn')
server = profile.get('server', '')
port = profile.get('port', 1194)
protocol = profile.get('protocol', 'udp')
auth = profile.get('authentication', {})
routing = profile.get('routing', {})

conn_name = f'OD-VPN-{name}'

# Remove existing
subprocess.run(['nmcli', 'connection', 'delete', conn_name], capture_output=True)

if vpn_type == 'openvpn':
    cmd = ['nmcli', 'connection', 'add', 'type', 'vpn', 'con-name', conn_name,
           'vpn-type', 'openvpn',
           'vpn.data', f'remote={server}, port={port}, proto-{protocol}=yes']
    if auth.get('certificates', {}).get('ca'):
        cert_dir = '/etc/NetworkManager/certs'
        os.makedirs(cert_dir, exist_ok=True)
        ca_path = f'{cert_dir}/od-vpn-{name}-ca.pem'
        with open(ca_path, 'w') as f:
            f.write(auth['certificates']['ca'])
        subprocess.run(['nmcli', 'connection', 'modify', conn_name, '+vpn.data', f'ca={ca_path}'], capture_output=True)

elif vpn_type == 'wireguard':
    wg_conf = f'/etc/wireguard/{conn_name}.conf'
    os.makedirs('/etc/wireguard', exist_ok=True)
    conf_content = f'[Interface]\\nPrivateKey = {auth.get(\"privateKey\", \"\")}\\n\\n[Peer]\\nPublicKey = {auth.get(\"publicKey\", \"\")}\\nEndpoint = {server}:{port}\\nAllowedIPs = {\"0.0.0.0/0\" if not routing.get(\"splitTunnel\") else \", \".join(routing.get(\"includedRoutes\", [\"0.0.0.0/0\"]))}\\n'
    with open(wg_conf, 'w') as f:
        f.write(conf_content)
    os.chmod(wg_conf, 0o600)
    cmd = ['wg-quick', 'up', conn_name]

elif vpn_type in ('ikev2', 'l2tp'):
    cmd = ['nmcli', 'connection', 'add', 'type', 'vpn', 'con-name', conn_name,
           'vpn-type', 'strongswan' if vpn_type == 'ikev2' else 'l2tp',
           'vpn.data', f'gateway={server}']
else:
    print(json.dumps({'status': 'failed', 'error': f'Unsupported VPN type: {vpn_type}'}))
    sys.exit(0)

result = subprocess.run(cmd, capture_output=True, text=True)
if result.returncode == 0:
    # Configure DNS if specified
    if routing.get('dns'):
        subprocess.run(['nmcli', 'connection', 'modify', conn_name, 'ipv4.dns', ' '.join(routing['dns'])], capture_output=True)
    print(json.dumps({'status': 'success', 'profileId': conn_name, 'message': f'VPN profile {name} configured'}))
else:
    print(json.dumps({'status': 'failed', 'error': result.stderr.strip()}))
" <<< "$json"
}

handle_remove_vpn() {
    local json="$1"
    local profile_id
    profile_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('profileId',''))" 2>/dev/null)
    if nmcli connection delete "$profile_id" 2>/dev/null; then
        echo "{\"status\":\"success\",\"message\":\"VPN profile removed\"}"
    else
        echo "{\"status\":\"failed\",\"error\":\"VPN profile not found\"}"
    fi
}

handle_configure_email() {
    local json="$1"
    python3 -c "
import json, sys, os, subprocess

data = json.loads(sys.stdin.read())
profile = data.get('data', {}).get('profile', {})
account_name = profile.get('accountName', 'Corporate Email')
account_type = profile.get('accountType', 'imap')
email = profile.get('emailAddress', '')
server = profile.get('server', {})
auth = profile.get('authentication', {})

# Linux email configuration via evolution-data-server or Thunderbird
config_dir = os.path.expanduser('~/.config/opendirectory/email-profiles')
os.makedirs(config_dir, exist_ok=True)

profile_config = {
    'accountName': account_name,
    'accountType': account_type,
    'emailAddress': email,
    'incoming': server.get('incoming', {}),
    'outgoing': server.get('outgoing', {}),
    'username': auth.get('username', email),
    'authMethod': auth.get('method', 'password')
}

profile_path = os.path.join(config_dir, f'{account_name.replace(\" \", \"_\")}.json')
with open(profile_path, 'w') as f:
    json.dump(profile_config, f, indent=2)

# If Thunderbird is available, configure via autoconfig
thunderbird_dir = None
for d in os.listdir(os.path.expanduser('~/.thunderbird')) if os.path.exists(os.path.expanduser('~/.thunderbird')) else []:
    if d.endswith('.default') or d.endswith('.default-release'):
        thunderbird_dir = os.path.join(os.path.expanduser('~/.thunderbird'), d)
        break

print(json.dumps({
    'status': 'success',
    'profileId': account_name,
    'configPath': profile_path,
    'thunderbird': thunderbird_dir is not None,
    'message': f'Email profile {account_name} configured'
}))
" <<< "$json"
}

handle_remove_email() {
    local json="$1"
    local profile_id
    profile_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('profileId',''))" 2>/dev/null)
    local config_dir="$HOME/.config/opendirectory/email-profiles"
    local profile_path="${config_dir}/${profile_id// /_}.json"
    if [ -f "$profile_path" ]; then
        rm -f "$profile_path"
        echo "{\"status\":\"success\",\"message\":\"Email profile removed\"}"
    else
        echo "{\"status\":\"failed\",\"error\":\"Email profile not found\"}"
    fi
}

# ============================================================================
# PRINTER MANAGEMENT (Linux: lpadmin / CUPS)
# ============================================================================
ensure_cups_installed() {
    if ! command -v lpadmin &>/dev/null; then
        log "CUPS not found, installing..." "WARN"
        if command -v apt-get &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y cups cups-client 2>&1
        elif command -v dnf &>/dev/null; then
            dnf install -y cups 2>&1
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm cups 2>&1
        fi
        systemctl enable cups 2>/dev/null; systemctl start cups 2>/dev/null
    fi
}

handle_deploy_printers() {
    local json="$1"
    ensure_cups_installed
    python3 -c "
import sys, json, subprocess

data = json.load(sys.stdin).get('data', {})
printers = data.get('printers', [])
remove_existing = data.get('removeExisting', False)
set_default = data.get('setDefault')
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
    [ "$notify_user" != "False" ] && show_notification "Drucker konfiguriert" "Drucker wurden installiert."
}

handle_remove_printer() {
    local pname="$1"
    [[ "$pname" != OD_* ]] && pname="OD_$pname"
    if lpstat -p "$pname" &>/dev/null; then
        lpadmin -x "$pname" 2>&1
        log "Printer removed: $pname"
        show_notification "Drucker entfernt" "$pname"
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
    duplex_map = {'long': 'two-sided-long-edge', 'short': 'two-sided-short-edge', 'none': 'one-sided'}
    val = duplex_map.get(settings['duplex'], 'one-sided')
    subprocess.run(['lpoptions', '-p', pname, '-o', f'sides={val}'], capture_output=True)
if settings.get('color') is not None:
    val = 'Color' if settings['color'] else 'Gray'
    subprocess.run(['lpoptions', '-p', pname, '-o', f'ColorModel={val}'], capture_output=True)
if settings.get('paperSize'):
    subprocess.run(['lpoptions', '-p', pname, '-o', f'media={settings[\"paperSize\"]}'], capture_output=True)
print(f'Settings updated: {pname}')
" <<< "$json"
}

handle_apply_printer_policy() {
    local json="$1"
    ensure_cups_installed
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
    handle_deploy_printers "$json"
    local policy_id
    policy_id=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('policyId',''))" 2>/dev/null)
    [ -n "$policy_id" ] && [ "$policy_id" != "None" ] && show_notification "Drucker-Richtlinie angewendet" "Drucker gemäss Policy konfiguriert."
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
