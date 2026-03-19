#!/bin/bash
# ============================================================
# OpenDirectory - Quick Setup Script
# Ein-Befehl-Installation für kleine Büros (5-50 Geräte)
#
# Verwendung:
#   curl -sSL https://raw.githubusercontent.com/.../quick-setup.sh | bash
#   oder: ./quick-setup.sh [--full|--lite|--with-printers]
# ============================================================

set -euo pipefail

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

COMPOSE_FILE="docker-compose.lite.yml"
PROFILES=""

log()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[i]${NC} $1"; }

# Banner
echo ""
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║          OpenDirectory - Quick Setup              ║"
echo "  ║       Open-Source Device Management Platform      ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo ""

# Parse arguments
for arg in "$@"; do
  case $arg in
    --full)
      COMPOSE_FILE="docker-compose.yml"
      info "Verwende Full-Stack (Enterprise-Modus)"
      ;;
    --lite)
      COMPOSE_FILE="docker-compose.lite.yml"
      info "Verwende Lite-Modus (Small Office)"
      ;;
    --with-printers)
      PROFILES="--profile with-printers"
      info "Drucker-Service wird aktiviert"
      ;;
    --help|-h)
      echo "Verwendung: ./quick-setup.sh [OPTIONEN]"
      echo ""
      echo "Optionen:"
      echo "  --lite            Small-Office-Modus (Standard, ~4GB RAM)"
      echo "  --full            Enterprise-Modus (alle Services, ~16GB RAM)"
      echo "  --with-printers   Drucker-Management aktivieren"
      echo "  --help            Diese Hilfe anzeigen"
      exit 0
      ;;
  esac
done

# Voraussetzungen prüfen
info "Prüfe Voraussetzungen..."

if ! command -v docker &> /dev/null; then
  error "Docker ist nicht installiert. Bitte installiere Docker: https://docs.docker.com/get-docker/"
fi

if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
  error "Docker Compose ist nicht installiert."
fi

# Docker Compose command detection
if command -v docker compose &> /dev/null; then
  DC="docker compose"
else
  DC="docker-compose"
fi

# Systemressourcen prüfen
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))

if [ "$TOTAL_MEM_GB" -lt 4 ] && [ "$COMPOSE_FILE" = "docker-compose.lite.yml" ]; then
  warn "System hat nur ${TOTAL_MEM_GB}GB RAM. Empfohlen: 4GB+ für Lite-Modus."
  read -p "Trotzdem fortfahren? (j/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[JjYy]$ ]] && exit 1
fi

if [ "$TOTAL_MEM_GB" -lt 12 ] && [ "$COMPOSE_FILE" = "docker-compose.yml" ]; then
  warn "System hat nur ${TOTAL_MEM_GB}GB RAM. Empfohlen: 16GB+ für Full-Modus."
  warn "Verwende stattdessen: ./quick-setup.sh --lite"
  read -p "Trotzdem fortfahren? (j/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[JjYy]$ ]] && exit 1
fi

log "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+') gefunden"
log "System: ${TOTAL_MEM_GB}GB RAM verfügbar"

# .env erstellen wenn nicht vorhanden
if [ ! -f .env ]; then
  info "Erstelle .env Konfiguration..."

  # Sichere Passwörter generieren
  generate_password() {
    openssl rand -base64 32 | tr -d '/+=' | head -c 32
  }

  cat > .env << EOF
# ============================================
# OpenDirectory - Automatisch generierte Konfiguration
# Erstellt am: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================

# Datenbank-Passwörter (automatisch generiert)
DB_PASSWORD=$(generate_password)
MONGO_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
RABBITMQ_PASSWORD=$(generate_password)

# LDAP
LLDAP_JWT_SECRET=$(generate_password)
LLDAP_ADMIN_PASSWORD=$(generate_password)

# Sicherheit
JWT_SECRET=$(generate_password)
ENCRYPTION_KEY=$(generate_password)

# Admin-Zugang
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$(generate_password)

# Grafana (nur im Full-Modus)
GRAFANA_PASSWORD=$(generate_password)

# Umgebung
NODE_ENV=production

# Feature-Flags
FEATURE_MDM_ENABLED=true
FEATURE_UPDATE_MANAGEMENT_ENABLED=true
FEATURE_PRINT_MANAGEMENT_ENABLED=true
FEATURE_LICENSE_MANAGEMENT_ENABLED=false
FEATURE_CONDITIONAL_ACCESS_ENABLED=false
FEATURE_CERTIFICATE_MANAGEMENT_ENABLED=false
EOF

  log ".env erstellt mit sicheren Passwörtern"
  echo ""
  warn "WICHTIG: Admin-Passwort notieren!"
  echo -e "  Admin-User:     ${GREEN}admin${NC}"
  echo -e "  Admin-Passwort: ${GREEN}$(grep ADMIN_PASSWORD .env | cut -d= -f2)${NC}"
  echo -e "  LLDAP Admin:    ${GREEN}$(grep LLDAP_ADMIN_PASSWORD .env | cut -d= -f2)${NC}"
  echo ""
  warn "Diese Passwörter werden nur einmal angezeigt!"
  echo ""
  read -p "Passwörter notiert? Weiter mit Enter..." -r
else
  log ".env existiert bereits"
fi

# Services starten
info "Starte OpenDirectory mit $COMPOSE_FILE..."
echo ""

$DC -f "$COMPOSE_FILE" $PROFILES up -d --build 2>&1 | while IFS= read -r line; do
  echo "  $line"
done

echo ""
info "Warte auf Service-Start (max. 120 Sekunden)..."

# Health-Check: warte auf API Backend
SECONDS=0
TIMEOUT=120
while [ $SECONDS -lt $TIMEOUT ]; do
  if curl -sf http://localhost:8080/api/health > /dev/null 2>&1; then
    break
  fi
  echo -ne "\r  Warte... ${SECONDS}s / ${TIMEOUT}s"
  sleep 3
done

echo ""

if curl -sf http://localhost:8080/api/health > /dev/null 2>&1; then
  log "API Backend läuft"
else
  warn "API Backend antwortet noch nicht - Services starten möglicherweise noch"
fi

# Status anzeigen
echo ""
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║          OpenDirectory ist bereit!                ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo ""
echo "  Zugriff:"
echo -e "    Web-UI:        ${GREEN}http://localhost:3000${NC}"
echo -e "    API:           ${GREEN}http://localhost:8080${NC}"
echo -e "    API Gateway:   ${GREEN}http://localhost:3010${NC}"
echo -e "    LLDAP Admin:   ${GREEN}http://localhost:17170${NC}"
echo ""
echo "  Nächste Schritte:"
echo "    1. Öffne http://localhost:3000 im Browser"
echo "    2. Melde dich mit admin / <dein Passwort> an"
echo "    3. Registriere deine Geräte (siehe SMALL_OFFICE_GUIDE.md)"
echo ""
echo "  Nützliche Befehle:"
echo "    Status:   $DC -f $COMPOSE_FILE ps"
echo "    Logs:     $DC -f $COMPOSE_FILE logs -f"
echo "    Stop:     $DC -f $COMPOSE_FILE down"
echo "    Neustart: $DC -f $COMPOSE_FILE restart"
echo ""

# Container-Status
info "Container-Status:"
$DC -f "$COMPOSE_FILE" $PROFILES ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
  $DC -f "$COMPOSE_FILE" $PROFILES ps
