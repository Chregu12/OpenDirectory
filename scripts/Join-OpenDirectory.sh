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
  read -rsp "Domain admin password for $ADMIN_USER@$REALM_UPPER: " ADMIN_PASS
  echo ""
fi

# ─── Step 3: Register computer with OpenDirectory ────────────────────────────

echo ""
echo "[2/5] Registering computer with OpenDirectory…"

JOIN_BODY="$(cat <<JSON
{
  "computerName": "$HOSTNAME",
  "requestingUser": "$ADMIN_USER",
  "operatingSystem": "${DISTRO:-Linux}",
  "osVersion": "$OS_VERSION",
  "manufacturer": "${MANUFACTURER}",
  "model": "${MODEL}"
$(if [[ -n "$OU_DN" ]]; then echo ",\"ouDn\": \"$OU_DN\""; fi)
}
JSON
)"

JOIN_RESPONSE="$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$JOIN_BODY" \
  "${API_BASE}/api/samba/computers/join" 2>&1)" || {
    echo "ERROR: OpenDirectory registration failed." >&2
    echo "Response: $JOIN_RESPONSE" >&2
    exit 1
  }

DC_IP="$(echo "$JOIN_RESPONSE" | grep -o '"dcIpAddress":"[^"]*"' | cut -d'"' -f4)"
NETBIOS="$(echo "$JOIN_RESPONSE" | grep -o '"netbiosDomain":"[^"]*"' | cut -d'"' -f4)"
COMPUTER_DN="$(echo "$JOIN_RESPONSE" | grep -o '"computerDn":"[^"]*"' | cut -d'"' -f4)"

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

HW_BODY="$(cat <<JSON
{
  "hostname": "$HOSTNAME",
  "manufacturer": "${MANUFACTURER}",
  "model": "${MODEL}",
  "os": "linux",
  "osVersion": "${DISTRO:-Linux} $OS_VERSION",
  "hardwareIds": ${HW_COMBINED}
}
JSON
)"

HW_RESPONSE="$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$HW_BODY" \
  "${API_BASE}/api/devices/report-hardware" 2>&1)" || {
    echo "  WARNING: Hardware report failed (non-fatal)."
    HW_RESPONSE=""
  }

if [[ -n "$HW_RESPONSE" ]]; then
  REC_COUNT="$(echo "$HW_RESPONSE" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2 || echo 0)"
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

  if echo "$ADMIN_PASS" | net ads join -U "${ADMIN_USER}%${ADMIN_PASS}" ${SERVER_ARG} 2>&1; then
    JOINED=true
    echo "  Joined domain via winbind (net ads join)."
  else
    echo "  WARNING: winbind join also failed. Check credentials and DNS."
  fi
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
