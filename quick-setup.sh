#!/bin/bash
# ============================================================
# OpenDirectory - Quick Setup mit Modul-Wizard
# Interaktive Installation für kleine bis mittlere Büros
#
# Verwendung:
#   ./quick-setup.sh                  # Interaktiver Wizard
#   ./quick-setup.sh --full           # Alle Module (Enterprise)
#   ./quick-setup.sh --minimal        # Nur Kern, keine Module
#   ./quick-setup.sh --modules network,printers  # Bestimmte Module
# ============================================================

set -euo pipefail

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

COMPOSE_FILE="docker-compose.lite.yml"
SELECTED_PROFILES=()
SKIP_WIZARD=false

log()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[i]${NC} $1"; }

# ============================================================
# Banner
# ============================================================
show_banner() {
  echo ""
  echo -e "  ${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
  echo -e "  ${BOLD}║${NC}         ${CYAN}OpenDirectory${NC} — Quick Setup                   ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}         Open-Source Device Management                 ${BOLD}║${NC}"
  echo -e "  ${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ============================================================
# Argument-Parsing
# ============================================================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --full)
        COMPOSE_FILE="docker-compose.yml"
        SKIP_WIZARD=true
        info "Enterprise-Modus: Alle Services"
        ;;
      --minimal)
        SKIP_WIZARD=true
        info "Minimal-Modus: Nur Kern-Services"
        ;;
      --modules)
        shift
        IFS=',' read -ra MODS <<< "$1"
        for mod in "${MODS[@]}"; do
          SELECTED_PROFILES+=("$mod")
        done
        SKIP_WIZARD=true
        info "Module: ${MODS[*]}"
        ;;
      --help|-h)
        echo "Verwendung: ./quick-setup.sh [OPTIONEN]"
        echo ""
        echo "Optionen:"
        echo "  (keine)                   Interaktiver Modul-Wizard"
        echo "  --minimal                 Nur Kern (~2.0 GB RAM)"
        echo "  --modules network,printers  Bestimmte Module aktivieren"
        echo "  --full                    Enterprise-Modus (~16 GB RAM)"
        echo "  --help                    Diese Hilfe"
        echo ""
        echo "Verfügbare Module:"
        echo "  network     DNS, DHCP, SMB/NFS File Shares       (~192 MB)"
        echo "  printers    Drucker + Scanner (CUPS)              (~192 MB)"
        echo "  monitoring  Grafana + Prometheus Dashboards       (~448 MB)"
        echo "  security    CIS/NIST Scanner + Auto-Remediation   (~320 MB)"
        echo "  lifecycle   Device Lifecycle + Graph Explorer      (~448 MB)"
        echo ""
        echo "Beispiele:"
        echo "  ./quick-setup.sh                          # Wizard"
        echo "  ./quick-setup.sh --modules network        # Kern + DNS/DHCP"
        echo "  ./quick-setup.sh --modules network,printers,monitoring"
        exit 0
        ;;
      *)
        warn "Unbekannte Option: $1 (--help für Hilfe)"
        ;;
    esac
    shift
  done
}

# ============================================================
# Modul-Wizard
# ============================================================
run_wizard() {
  echo -e "  ${BOLD}Welche Module brauchst du?${NC}"
  echo -e "  ${DIM}Kern-System (User, Geräte, Policies, API, Web-UI) ist immer aktiv.${NC}"
  echo ""

  # Modul-Definitionen: Name | Beschreibung | RAM | Default
  local modules=(
    "network|DNS, DHCP, SMB/NFS Netzlaufwerke|192 MB|empfohlen"
    "printers|Drucker & Scanner Management (CUPS)|192 MB|"
    "monitoring|Grafana Dashboards + Prometheus Metriken|448 MB|"
    "security|Security Scanner (CIS/NIST) + Auto-Fix|320 MB|"
    "lifecycle|Geräte-Lifecycle + Graph Explorer + Policy Simulator|448 MB|"
  )

  local ram_total=2112  # Kern in MB
  local selections=()

  for i in "${!modules[@]}"; do
    IFS='|' read -r name desc ram default <<< "${modules[$i]}"
    local num=$((i + 1))
    local ram_num="${ram//[^0-9]/}"

    # Anzeige
    if [ -n "$default" ]; then
      echo -e "  ${BOLD}[$num]${NC} ${CYAN}$name${NC}"
      echo -e "      $desc"
      echo -e "      ${DIM}+$ram RAM${NC}  ${GREEN}($default)${NC}"
    else
      echo -e "  ${BOLD}[$num]${NC} ${CYAN}$name${NC}"
      echo -e "      $desc"
      echo -e "      ${DIM}+$ram RAM${NC}"
    fi
    echo ""
  done

  echo -e "  ${DIM}────────────────────────────────────────────${NC}"
  echo -e "  Kern-System:  ${BOLD}~2.0 GB RAM${NC} (immer aktiv)"
  echo ""
  echo -e "  ${BOLD}Eingabe:${NC} Nummern durch Komma getrennt, oder ${BOLD}Enter${NC} für empfohlene"
  echo -e "  ${DIM}Beispiel: 1,2  oder  1,2,3,4,5  oder  Enter für Standard${NC}"
  echo ""
  echo -ne "  Module aktivieren [1]: "
  read -r choice

  # Default: nur network
  if [ -z "$choice" ]; then
    choice="1"
  fi

  # "alle" / "all"
  if [[ "$choice" == "alle" ]] || [[ "$choice" == "all" ]]; then
    choice="1,2,3,4,5"
  fi

  # "keine" / "none" / "0"
  if [[ "$choice" == "keine" ]] || [[ "$choice" == "none" ]] || [[ "$choice" == "0" ]]; then
    choice=""
  fi

  # Parse Auswahl
  IFS=',' read -ra nums <<< "$choice"
  for num in "${nums[@]}"; do
    num=$(echo "$num" | tr -d ' ')
    case $num in
      1) SELECTED_PROFILES+=("network"); ram_total=$((ram_total + 192)) ;;
      2) SELECTED_PROFILES+=("printers"); ram_total=$((ram_total + 192)) ;;
      3) SELECTED_PROFILES+=("monitoring"); ram_total=$((ram_total + 448)) ;;
      4) SELECTED_PROFILES+=("security"); ram_total=$((ram_total + 320)) ;;
      5) SELECTED_PROFILES+=("lifecycle"); ram_total=$((ram_total + 448)) ;;
      *) warn "Unbekannte Auswahl: $num (übersprungen)" ;;
    esac
  done

  # RAM-Zusammenfassung
  echo ""
  echo -e "  ${BOLD}╔═══════════════════════════════════════════════╗${NC}"
  echo -e "  ${BOLD}║${NC}  Konfiguration:                               ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}                                               ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}  ${GREEN}Kern${NC}    User, Geräte, Policies, API, Web-UI  ${BOLD}║${NC}"

  for profile in "${SELECTED_PROFILES[@]}"; do
    case $profile in
      network)    echo -e "  ${BOLD}║${NC}  ${CYAN}+${NC} Netzwerk   DNS, DHCP, SMB/NFS             ${BOLD}║${NC}" ;;
      printers)   echo -e "  ${BOLD}║${NC}  ${CYAN}+${NC} Drucker    CUPS, Auto-Discovery            ${BOLD}║${NC}" ;;
      monitoring) echo -e "  ${BOLD}║${NC}  ${CYAN}+${NC} Monitoring Grafana, Prometheus              ${BOLD}║${NC}" ;;
      security)   echo -e "  ${BOLD}║${NC}  ${CYAN}+${NC} Security   Scanner, Auto-Remediation        ${BOLD}║${NC}" ;;
      lifecycle)  echo -e "  ${BOLD}║${NC}  ${CYAN}+${NC} Lifecycle  Graph Explorer, Simulator        ${BOLD}║${NC}" ;;
    esac
  done

  local ram_gb
  ram_gb=$(awk "BEGIN {printf \"%.1f\", $ram_total / 1024}")
  echo -e "  ${BOLD}║${NC}                                               ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}  Geschätzter RAM: ${BOLD}~${ram_gb} GB${NC}                    ${BOLD}║${NC}"
  echo -e "  ${BOLD}╚═══════════════════════════════════════════════╝${NC}"
  echo ""

  # RAM-Warnung
  local total_mem_kb
  total_mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
  local total_mem_mb=$((total_mem_kb / 1024))

  if [ "$total_mem_mb" -gt 0 ] && [ "$ram_total" -gt "$((total_mem_mb * 85 / 100))" ]; then
    warn "RAM-Verbrauch (~${ram_gb} GB) liegt über 85% deines Systems (${total_mem_mb} MB)."
    warn "Erwäge Module zu deaktivieren oder RAM aufzurüsten."
    echo ""
    echo -ne "  Trotzdem fortfahren? (j/N): "
    read -r -n 1 confirm
    echo ""
    [[ ! $confirm =~ ^[JjYy]$ ]] && exit 1
  fi

  echo -ne "  ${BOLD}Starten?${NC} (J/n): "
  read -r -n 1 confirm
  echo ""
  [[ $confirm =~ ^[Nn]$ ]] && exit 0
}

# ============================================================
# Voraussetzungen prüfen
# ============================================================
check_prerequisites() {
  info "Prüfe Voraussetzungen..."

  if ! command -v docker &> /dev/null; then
    error "Docker nicht gefunden. Installation: https://docs.docker.com/get-docker/"
  fi

  if command -v docker compose &> /dev/null; then
    DC="docker compose"
  elif command -v docker-compose &> /dev/null; then
    DC="docker-compose"
  else
    error "Docker Compose nicht gefunden."
  fi

  local mem_kb
  mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
  local mem_gb=$((mem_kb / 1024 / 1024))

  log "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+') gefunden"
  log "RAM: ${mem_gb} GB verfügbar"
}

# ============================================================
# .env generieren
# ============================================================
generate_env() {
  if [ -f .env ]; then
    log ".env existiert bereits — wird beibehalten"
    return
  fi

  info "Generiere .env mit sicheren Passwörtern..."

  gen() { openssl rand -base64 32 | tr -d '/+=' | head -c 32; }

  local admin_pw
  admin_pw=$(gen)
  local lldap_pw
  lldap_pw=$(gen)

  cat > .env << EOF
# OpenDirectory — Automatisch generiert am $(date '+%Y-%m-%d %H:%M:%S')

# Datenbanken
DB_PASSWORD=$(gen)
MONGO_PASSWORD=$(gen)
REDIS_PASSWORD=$(gen)
RABBITMQ_PASSWORD=$(gen)

# LDAP
LLDAP_JWT_SECRET=$(gen)
LLDAP_ADMIN_PASSWORD=${lldap_pw}

# Sicherheit
JWT_SECRET=$(gen)
ENCRYPTION_KEY=$(gen)

# Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${admin_pw}

# Monitoring
GRAFANA_PASSWORD=$(gen)

# Umgebung
NODE_ENV=production
EOF

  log ".env erstellt"
  echo ""
  echo -e "  ${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
  echo -e "  ${BOLD}║${NC}  ${YELLOW}ZUGANGSDATEN — JETZT NOTIEREN!${NC}                    ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}                                                   ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}  Web-UI Login:                                    ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}    User:     ${GREEN}admin${NC}                                  ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}    Passwort: ${GREEN}${admin_pw}${NC}  ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}                                                   ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}  LLDAP Admin (User-Verzeichnis):                  ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}    Passwort: ${GREEN}${lldap_pw}${NC}  ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}                                                   ${BOLD}║${NC}"
  echo -e "  ${BOLD}║${NC}  ${RED}Diese Passwörter werden nur einmal angezeigt!${NC}    ${BOLD}║${NC}"
  echo -e "  ${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
  echo ""
  read -p "  Passwörter notiert? Weiter mit Enter..." -r
}

# ============================================================
# Services starten
# ============================================================
start_services() {
  # Profiles zusammenbauen
  local profile_args=""
  for p in "${SELECTED_PROFILES[@]}"; do
    profile_args="$profile_args --profile $p"
  done

  local service_count
  if [ ${#SELECTED_PROFILES[@]} -eq 0 ]; then
    service_count=12
    info "Starte Kern-System (12 Container)..."
  else
    # Grobe Schätzung
    service_count=12
    for p in "${SELECTED_PROFILES[@]}"; do
      case $p in
        network) service_count=$((service_count + 1)) ;;
        printers) service_count=$((service_count + 1)) ;;
        monitoring) service_count=$((service_count + 2)) ;;
        security) service_count=$((service_count + 2)) ;;
        lifecycle) service_count=$((service_count + 3)) ;;
      esac
    done
    info "Starte $service_count Container (Kern + ${SELECTED_PROFILES[*]})..."
  fi

  echo ""
  # shellcheck disable=SC2086
  $DC -f "$COMPOSE_FILE" $profile_args up -d --build 2>&1 | while IFS= read -r line; do
    echo "  $line"
  done

  echo ""
  info "Warte auf Service-Start..."

  SECONDS=0
  local timeout=120
  while [ $SECONDS -lt $timeout ]; do
    if curl -sf http://localhost:8080/api/health > /dev/null 2>&1; then
      break
    fi
    echo -ne "\r  Warte... ${SECONDS}s / ${timeout}s  "
    sleep 3
  done
  echo ""

  if curl -sf http://localhost:8080/api/health > /dev/null 2>&1; then
    log "API Backend läuft"
  else
    warn "API Backend antwortet noch nicht — Container starten möglicherweise noch"
  fi
}

# ============================================================
# Ergebnis anzeigen
# ============================================================
show_result() {
  local profile_args=""
  for p in "${SELECTED_PROFILES[@]}"; do
    profile_args="$profile_args --profile $p"
  done

  echo ""
  echo -e "  ${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
  echo -e "  ${BOLD}║${NC}           ${GREEN}OpenDirectory ist bereit!${NC}                    ${BOLD}║${NC}"
  echo -e "  ${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${BOLD}Zugriff:${NC}"
  echo -e "    Web-UI:        ${GREEN}http://localhost:3000${NC}"
  echo -e "    API:           ${GREEN}http://localhost:8080${NC}"
  echo -e "    API Gateway:   ${GREEN}http://localhost:3010${NC}"
  echo -e "    LLDAP Admin:   ${GREEN}http://localhost:17170${NC}"

  for p in "${SELECTED_PROFILES[@]}"; do
    case $p in
      monitoring)
        echo -e "    Grafana:       ${GREEN}http://localhost:3500${NC}"
        echo -e "    Prometheus:    ${GREEN}http://localhost:9090${NC}"
        ;;
      printers)
        echo -e "    CUPS Admin:    ${GREEN}http://localhost:631${NC}"
        ;;
    esac
  done

  echo ""
  echo -e "  ${BOLD}Aktive Module:${NC}"
  echo -e "    ${GREEN}Kern${NC} — User, Geräte, Policies, API, Web-UI"
  for p in "${SELECTED_PROFILES[@]}"; do
    case $p in
      network)    echo -e "    ${CYAN}Netzwerk${NC} — DNS :53, DHCP :67, SMB :445, NFS :2049" ;;
      printers)   echo -e "    ${CYAN}Drucker${NC} — CUPS :631, Auto-Discovery, Scanner" ;;
      monitoring) echo -e "    ${CYAN}Monitoring${NC} — Grafana :3500, Prometheus :9090" ;;
      security)   echo -e "    ${CYAN}Security${NC} — Scanner :3902, Auto-Remediation :3904" ;;
      lifecycle)  echo -e "    ${CYAN}Lifecycle${NC} — Graph :3900, Simulator :3901, Lifecycle :3903" ;;
    esac
  done

  echo ""
  echo -e "  ${BOLD}Nützliche Befehle:${NC}"
  echo "    Status:     $DC -f $COMPOSE_FILE $profile_args ps"
  echo "    Logs:       $DC -f $COMPOSE_FILE $profile_args logs -f"
  echo "    Stop:       $DC -f $COMPOSE_FILE $profile_args down"
  echo ""
  echo -e "  ${BOLD}Module nachträglich aktivieren:${NC}"
  echo "    $DC -f $COMPOSE_FILE --profile monitoring up -d"
  echo "    $DC -f $COMPOSE_FILE --profile security up -d"
  echo ""

  # Container-Status
  info "Container-Status:"
  # shellcheck disable=SC2086
  $DC -f "$COMPOSE_FILE" $profile_args ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
    $DC -f "$COMPOSE_FILE" $profile_args ps
}

# ============================================================
# Main
# ============================================================

show_banner
parse_args "$@"
check_prerequisites

if [ "$SKIP_WIZARD" = false ] && [ "$COMPOSE_FILE" != "docker-compose.yml" ]; then
  run_wizard
fi

generate_env
start_services
show_result
