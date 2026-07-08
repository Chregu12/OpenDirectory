#!/usr/bin/env bash
# Join-OpenDirectory.sh — Join a Linux device to an OpenDirectory (Samba AD) domain
#   and report hardware for automatic driver matching.
#
# Usage:
#   sudo ./Join-OpenDirectory.sh \
#       --api-base https://od.corp.example.com \
#       --realm CORP.EXAMPLE.COM \
#       --admin-user Administrator \
#       [--ou "OU=Linux,DC=corp,DC=example,DC=com"] \
#       [--join-method realm|winbind|samba]
#
# Requirements:
#   realm method  : realmd, sssd, adcli, krb5-user  (recommended — most modern distros)
#   winbind method: samba-common, winbind, krb5-user
#   samba  method : samba-tool (manual — for servers)
#
# After joining, the script posts a hardware report including PCI/USB IDs
# to device-service and prints driver recommendations.

set -euo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────────────

API_BASE=""
REALM=""
ADMIN_USER="Administrator"
ADMIN_PASS=""
OU_DN=""
JOIN_METHOD="realm"   # realm | winbind | samba

# ─── Parse arguments ──────────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 --api-base URL --realm DOMAIN --admin-user USER [--ou DN] [--join-method realm|winbind|samba]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base)    API_BASE="$2";     shift 2 ;;
    --realm)       REALM="$2";        shift 2 ;;
    --admin-user)  ADMIN_USER="$2";   shift 2 ;;
    --admin-pass)  ADMIN_PASS="$2";   shift 2 ;;
    --ou)          OU_DN="$2";        shift 2 ;;
    --join-method) JOIN_METHOD="$2";  shift 2 ;;
    *) usage ;;
  esac
done

[[ -z "$API_BASE" || -z "$REALM" ]] && usage

API_BASE="${API_BASE%/}"
REALM_UPPER="${REALM^^}"
HOSTNAME="$(hostname -s)"

# ─── Root check ───────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo)." >&2
  exit 1
fi

# ─── Step 1: Collect hardware inventory ───────────────────────────────────────

echo ""
echo "[1/5] Collecting hardware inventory…"

MANUFACTURER=""
MODEL=""
OS_LABEL="linux"

if command -v dmidecode &>/dev/null; then
  MANUFACTURER="$(dmidecode -s system-manufacturer 2>/dev/null | head -1 | tr -d '\r')"
  MODEL="$(dmidecode -s system-product-name 2>/dev/null | head -1 | tr -d '\r')"
fi

# Fallback: /sys/class/dmi
if [[ -z "$MANUFACTURER" && -f /sys/class/dmi/id/sys_vendor ]]; then
  MANUFACTURER="$(cat /sys/class/dmi/id/sys_vendor)"
fi
if [[ -z "$MODEL" && -f /sys/class/dmi/id/product_name ]]; then
  MODEL="$(cat /sys/class/dmi/id/product_name)"
fi

OS_VERSION="$(uname -r)"
ARCH="$(uname -m)"
DISTRO=""
if [[ -f /etc/os-release ]]; then
  DISTRO="$(. /etc/os-release && echo "$PRETTY_NAME")"
fi

echo "  Manufacturer : ${MANUFACTURER:-unknown}"
echo "  Model        : ${MODEL:-unknown}"
echo "  Hostname     : $HOSTNAME"
echo "  OS           : ${DISTRO:-Linux} (kernel $OS_VERSION, $ARCH)"

# Collect PCI devices (lspci -n: "00:02.0 0300: 8086:9a49 (rev 01)")
# → {"deviceId":"8086:9a49","class":"0300"}  (class without trailing colon)
PCI_JSON="[]"
if command -v lspci &>/dev/null; then
  PCI_JSON="$(lspci -n 2>/dev/null | awk '{
    cls = substr($2, 1, 4);
    printf "{\"deviceId\":\"%s\",\"class\":\"%s\"},\n", $3, cls
  }' | sed '$ s/,$//' | { echo "["; cat; echo "]"; })" || PCI_JSON="[]"
fi

# Collect USB devices (lsusb: "Bus 002 Device 003: ID 0bda:8153 ...")
# → {"deviceId":"0bda:8153","class":"usb"}
USB_JSON="[]"
if command -v lsusb &>/dev/null; then
  USB_JSON="$(lsusb 2>/dev/null | awk '{
    printf "{\"deviceId\":\"%s\",\"class\":\"usb\"},\n", $6
  }' | sed '$ s/,$//' | { echo "["; cat; echo "]"; })" || USB_JSON="[]"
fi

PCI_COUNT="$(echo "$PCI_JSON" | grep -c '"deviceId"' || true)"
USB_COUNT="$(echo "$USB_JSON" | grep -c '"deviceId"' || true)"
echo "  PCI devices  : $PCI_COUNT found"
echo "  USB devices  : $USB_COUNT found"

# ─── Step 2: Prompt for password if not provided ─────────────────────────────

if [[ -z "$ADMIN_PASS" ]]; then
  # `read` fails (non-zero exit) if stdin is closed/non-interactive (e.g. run
  # via automation with no TTY), which under `set -e` would otherwise abort
  # the script here with no useful message. Handle that explicitly instead.
  read -rsp "Domain admin password for $ADMIN_USER@$REALM_UPPER: " ADMIN_PASS || true
  echo ""
  if [[ -z "$ADMIN_PASS" ]]; then
    echo "ERROR: No admin password provided. Pass --admin-pass in non-interactive contexts." >&2
    exit 1
  fi
fi

# ─── Step 3: Register computer with OpenDirectory ────────────────────────────

echo ""
echo "[2/5] Registering computer with OpenDirectory…"

# Built via python3 (already a dependency of this script, see the hardware
# merge step below) rather than string interpolation into a heredoc: any of
# these values (hostname, admin user, manufacturer/model from dmidecode, OU
# DN) could contain a double quote or backslash and corrupt/inject into the
# hand-rolled JSON otherwise.
JOIN_BODY="$(OD_HOSTNAME="$HOSTNAME" OD_ADMIN_USER="$ADMIN_USER" OD_OS_LABEL="${DISTRO:-Linux}" \
  OD_OS_VERSION="$OS_VERSION" OD_MANUFACTURER="$MANUFACTURER" OD_MODEL="$MODEL" OD_OU_DN="$OU_DN" \
  python3 -c "
import os, json
body = {
    'computerName': os.environ.get('OD_HOSTNAME', ''),
    'requestingUser': os.environ.get('OD_ADMIN_USER', ''),
    'operatingSystem': os.environ.get('OD_OS_LABEL', ''),
    'osVersion': os.environ.get('OD_OS_VERSION', ''),
    'manufacturer': os.environ.get('OD_MANUFACTURER', ''),
    'model': os.environ.get('OD_MODEL', ''),
}
ou = os.environ.get('OD_OU_DN', '')
if ou:
    body['ouDn'] = ou
print(json.dumps(body))
")"

JOIN_RESPONSE="$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$JOIN_BODY" \
  "${API_BASE}/api/samba/computers/join" 2>&1)" || {
    echo "ERROR: OpenDirectory registration failed." >&2
    echo "Response: $JOIN_RESPONSE" >&2
    exit 1
  }

# Parsed via python3 (already a hard dependency, see JOIN_BODY above) rather
# than grep/cut: the latter breaks on escaped quotes, nested JSON, or a
# different field order in the response. Missing/non-string fields print as
# an empty line, same as a grep/cut miss did before.
JOIN_PARSED="$(printf '%s' "$JOIN_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    if not isinstance(data, dict):
        data = {}
except Exception:
    data = {}
for k in ('dcIpAddress', 'netbiosDomain', 'computerDn'):
    v = data.get(k)
    print(v if isinstance(v, str) else '')
" 2>/dev/null || true)"
IFS=$'\n' read -r DC_IP NETBIOS COMPUTER_DN <<< "$JOIN_PARSED" || true

echo "  Computer DN  : ${COMPUTER_DN:-?}"
echo "  DC IP        : ${DC_IP:-?}"
echo "  NetBIOS      : ${NETBIOS:-?}"

# ─── Step 4: Post hardware report for driver matching ────────────────────────

echo ""
echo "[3/5] Submitting hardware report for driver matching…"

# Combine PCI + USB into one hardwareIds array.
# Each list is parsed independently so a malformed or empty one
# never destroys the other.
HW_COMBINED="$(PCI_LIST="$PCI_JSON" USB_LIST="$USB_JSON" python3 -c "
import os, json
def load(name):
    try:
        v = json.loads(os.environ.get(name, '[]'))
        return v if isinstance(v, list) else []
    except Exception:
        return []
print(json.dumps((load('PCI_LIST') + load('USB_LIST'))[:80]))
" 2>/dev/null || echo "[]")"

# Same JSON-injection concern as JOIN_BODY above: build via python3 instead
# of interpolating hostname/manufacturer/model into a heredoc.
HW_BODY="$(OD_HOSTNAME="$HOSTNAME" OD_MANUFACTURER="$MANUFACTURER" OD_MODEL="$MODEL" \
  OD_OS_VERSION="${DISTRO:-Linux} $OS_VERSION" HW_IDS="$HW_COMBINED" python3 -c "
import os, json
try:
    hw_ids = json.loads(os.environ.get('HW_IDS', '[]'))
    if not isinstance(hw_ids, list):
        hw_ids = []
except Exception:
    hw_ids = []
body = {
    'hostname': os.environ.get('OD_HOSTNAME', ''),
    'manufacturer': os.environ.get('OD_MANUFACTURER', ''),
    'model': os.environ.get('OD_MODEL', ''),
    'os': 'linux',
    'osVersion': os.environ.get('OD_OS_VERSION', ''),
    'hardwareIds': hw_ids,
}
print(json.dumps(body))
")"

HW_RESPONSE="$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$HW_BODY" \
  "${API_BASE}/api/devices/report-hardware" 2>&1)" || {
    echo "  WARNING: Hardware report failed (non-fatal)."
    HW_RESPONSE=""
  }

if [[ -n "$HW_RESPONSE" ]]; then
  # Same python3-based JSON parsing as JOIN_RESPONSE above, instead of grep/cut.
  REC_COUNT="$(printf '%s' "$HW_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    if not isinstance(data, dict):
        data = {}
except Exception:
    data = {}
count = data.get('count', 0)
print(count if isinstance(count, int) else 0)
" 2>/dev/null || echo 0)"
  echo "  Driver recommendations: ${REC_COUNT} found"
fi

# ─── Step 5: Join the domain ──────────────────────────────────────────────────

echo ""
echo "[4/5] Joining domain $REALM_UPPER using method: $JOIN_METHOD…"

JOINED=false

case "$JOIN_METHOD" in
  realm)
    if ! command -v realm &>/dev/null; then
      echo "  realmd not found — installing…"
      apt-get install -y realmd sssd sssd-tools adcli krb5-user packagekit 2>/dev/null || \
        dnf install -y realmd sssd adcli krb5-workstation 2>/dev/null || true
    fi

    REALM_ARGS=(join --user="$ADMIN_USER")
    [[ -n "$OU_DN" ]] && REALM_ARGS+=(--computer-ou="$OU_DN")
    [[ -n "$DC_IP" ]] && REALM_ARGS+=(--server="$DC_IP")
    REALM_ARGS+=("$REALM_UPPER")

    if echo "$ADMIN_PASS" | realm "${REALM_ARGS[@]}" 2>&1; then
      JOINED=true
      echo "  Joined domain via realmd."
    else
      echo "  realmd join failed — trying winbind fallback…"
      JOIN_METHOD="winbind"
    fi
    ;;
esac

if [[ "$JOIN_METHOD" == "winbind" && "$JOINED" == "false" ]]; then
  if ! command -v net &>/dev/null; then
    apt-get install -y samba-common winbind krb5-user 2>/dev/null || \
      dnf install -y samba-winbind krb5-workstation 2>/dev/null || true
  fi

  SERVER_ARG=""
  [[ -n "$DC_IP" ]] && SERVER_ARG="-S $DC_IP"

  # Use an authentication file (net's -A option) instead of -U user%pass:
  # the latter puts the plaintext password in the process arguments, which
  # is visible to any local user via `ps aux` for the life of the process.
  NET_AUTH_FILE="$(mktemp)"
  chmod 600 "$NET_AUTH_FILE"
  printf 'username = %s\npassword = %s\n' "$ADMIN_USER" "$ADMIN_PASS" > "$NET_AUTH_FILE"

  if net ads join -A "$NET_AUTH_FILE" ${SERVER_ARG} 2>&1; then
    JOINED=true
    echo "  Joined domain via winbind (net ads join)."
  else
    echo "  WARNING: winbind join also failed. Check credentials and DNS."
  fi
  rm -f "$NET_AUTH_FILE"
fi

if [[ "$JOIN_METHOD" == "samba" ]]; then
  if ! command -v samba-tool &>/dev/null; then
    echo "ERROR: samba-tool not found." >&2
    exit 1
  fi
  samba-tool domain join "$REALM_UPPER" MEMBER \
    -U "${ADMIN_USER}%${ADMIN_PASS}" \
    ${DC_IP:+--server="$DC_IP"} && JOINED=true
fi

# ─── Step 6: Show driver recommendations ─────────────────────────────────────

echo ""
echo "[5/5] Driver recommendations for $HOSTNAME:"

if [[ -n "$HW_RESPONSE" ]]; then
  echo "$HW_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    recs = data.get('recommendations', [])
    if not recs:
        print('  No recommendations found.')
    else:
        for r in recs[:12]:
            dtype = (r.get('deviceType') or 'other').upper().ljust(10)
            name  = r.get('name', '')
            ver   = r.get('version', '')
            apt   = r.get('aptPackage', '')
            oses  = ', '.join(r.get('os', []))
            score = r.get('matchScore', 0)
            via   = r.get('matchedVia', '')
            print(f'  [{dtype}] {name}' + (f' v{ver}' if ver else ''))
            if apt:
                print(f'             apt install {apt}')
            if r.get('downloadUrl'):
                print(f'             URL: {r[\"downloadUrl\"]}')
            print(f'             OS: {oses}  | via: {via}')
            print()
except Exception as e:
    print(f'  Could not parse recommendations: {e}')
" 2>/dev/null || echo "  (python3 not available — check the web UI for recommendations)"
else
  echo "  No hardware report available — check the OpenDirectory web UI:"
  echo "  ${API_BASE}/api/devices/${HOSTNAME}/driver-recommendations"
fi

# ─── Configure SSSD / PAM if realmd joined ────────────────────────────────────

if [[ "$JOINED" == "true" && "$JOIN_METHOD" == "realm" ]]; then
  echo ""
  echo "Configuring SSSD and PAM for AD authentication…"
  realm permit --all 2>/dev/null || true
  pam-auth-update --enable mkhomedir 2>/dev/null || true
  systemctl enable --now sssd 2>/dev/null || true
  echo "  SSSD configured. AD users can now log in."
fi

# ─── Done ─────────────────────────────────────────────────────────────────────

echo ""
if [[ "$JOINED" == "true" ]]; then
  echo "Done! $HOSTNAME is now a member of $REALM_UPPER."
  echo "Log in with: $ADMIN_USER@$REALM_UPPER  or  ${NETBIOS}\\$ADMIN_USER"
else
  echo "Domain join did not complete automatically. Manual steps may be required."
  echo "Computer account was pre-created: $COMPUTER_DN"
fi
