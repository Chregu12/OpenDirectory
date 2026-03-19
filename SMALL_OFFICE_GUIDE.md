# OpenDirectory - Small Office Guide

Anleitung für kleine Büros mit 5-50 Geräten (z.B. 3 Linux-Server, 5 Windows, 5 macOS).

## Schnellstart (5 Minuten)

```bash
# 1. Repository klonen
git clone https://github.com/Chregu12/OpenDirectory.git
cd OpenDirectory

# 2. Setup starten (generiert .env, startet Services)
./quick-setup.sh --lite

# 3. Optional: Drucker-Support aktivieren
./quick-setup.sh --lite --with-printers
```

Das startet **12 Container** mit ~4-6 GB RAM statt 24+ Container im Full-Modus.

## Was du bekommst

### Sofort verfügbar

| Feature | Beschreibung |
|---------|-------------|
| **Web-Dashboard** | `http://localhost:3000` — Übersicht aller Geräte |
| **User-Verzeichnis** | LLDAP mit LDAP-Anbindung, `http://localhost:17170` |
| **Geräte-Management** | Registrierung, Status, Compliance aller 13 Geräte |
| **Policy-Engine** | Regeln pro Gerät, Gruppe oder Plattform |
| **DNS-Server** | Eigener DNS für dein Netzwerk |
| **DHCP-Server** | IP-Vergabe für alle Geräte |
| **File-Shares** | SMB/NFS Netzlaufwerke |
| **API** | REST-API für Automatisierung |

### Nicht im Lite-Modus (bei Bedarf upgraden)

- Graph Explorer (Angriffspfad-Analyse)
- Policy Simulator (Was-Wäre-Wenn)
- Security Scanner (CIS/NIST Compliance)
- Auto-Remediation
- Antivirus-Management
- Grafana/Prometheus Monitoring

Upgrade auf Full: `docker-compose -f docker-compose.yml up -d`

---

## Geräte registrieren

### Windows (5 Geräte)

PowerShell als Administrator ausführen:

```powershell
# 1. Agent herunterladen
Invoke-WebRequest -Uri "http://DEIN-SERVER:8080/api/agents/windows" -OutFile "od-agent.ps1"

# 2. Agent installieren und registrieren
.\od-agent.ps1 -ServerUrl "http://DEIN-SERVER:8080" -EnrollmentToken "TOKEN_AUS_DASHBOARD"

# 3. Geräte-Status prüfen
.\od-agent.ps1 -Action status
```

**Alternativ: Manuell über API**
```powershell
$body = @{
    name = $env:COMPUTERNAME
    platform = "windows"
    osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://DEIN-SERVER:8080/api/devices/register" `
    -Method POST -Body $body -ContentType "application/json" `
    -Headers @{ Authorization = "Bearer $TOKEN" }
```

### macOS (5 Geräte)

```bash
# 1. Agent herunterladen und ausführen
curl -sSL http://DEIN-SERVER:8080/api/agents/macos | bash -s -- \
    --server "http://DEIN-SERVER:8080" \
    --token "TOKEN_AUS_DASHBOARD"

# 2. Alternativ: Manuell
curl -X POST http://DEIN-SERVER:8080/api/devices/register \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"$(hostname)\",
        \"platform\": \"macos\",
        \"osVersion\": \"$(sw_vers -productVersion)\",
        \"serialNumber\": \"$(ioreg -l | grep IOPlatformSerialNumber | awk '{print $4}' | tr -d '\"')\"
    }"
```

### Linux-Server (3 Geräte)

```bash
# 1. Agent installieren
curl -sSL http://DEIN-SERVER:8080/api/agents/linux | sudo bash -s -- \
    --server "http://DEIN-SERVER:8080" \
    --token "TOKEN_AUS_DASHBOARD"

# 2. Alternativ: Manuell
curl -X POST http://DEIN-SERVER:8080/api/devices/register \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"$(hostname)\",
        \"platform\": \"linux\",
        \"osVersion\": \"$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')\",
        \"serialNumber\": \"$(sudo dmidecode -s system-serial-number 2>/dev/null || echo 'unknown')\"
    }"

# 3. Systemd-Service für permanente Verbindung
sudo tee /etc/systemd/system/opendirectory-agent.service > /dev/null << 'EOF'
[Unit]
Description=OpenDirectory Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/od-agent --server http://DEIN-SERVER:8080
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now opendirectory-agent
```

---

## Tägliche Verwaltungsaufgaben

### OS-Updates verwalten

**Windows-Update-Policy erstellen:**
```bash
curl -X POST http://localhost:8080/api/policies \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Windows Updates - Büro",
        "platform": "windows",
        "type": "update",
        "settings": {
            "featureUpdateDeferral": 30,
            "qualityUpdateDeferral": 7,
            "maintenanceWindow": { "day": "Sunday", "start": "02:00", "end": "06:00" },
            "autoReboot": true,
            "rebootGracePeriod": 60
        },
        "targets": { "platforms": ["windows"] }
    }'
```

**Linux-Server Updates (nur Sicherheit):**
```bash
curl -X POST http://localhost:8080/api/policies \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Linux Security Updates",
        "platform": "linux",
        "type": "update",
        "settings": {
            "securityOnly": true,
            "autoReboot": false,
            "schedule": "daily",
            "time": "03:00"
        },
        "targets": { "platforms": ["linux"] }
    }'
```

### Apps verteilen

**Winget auf allen Windows-Geräten:**
```bash
# Chrome auf allen Windows-Geräten installieren
curl -X POST http://localhost:8080/api/applications/deploy \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "package": "Google.Chrome",
        "method": "winget",
        "targets": { "platforms": ["windows"] },
        "autoUpdate": true
    }'
```

**Homebrew auf allen Macs:**
```bash
curl -X POST http://localhost:8080/api/applications/deploy \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "package": "google-chrome",
        "method": "homebrew",
        "targets": { "platforms": ["macos"] }
    }'
```

### Remote-Aktionen

```bash
# Einzelnes Gerät neustarten
curl -X POST http://localhost:8080/api/devices/DEVICE-ID/actions/restart \
    -H "Authorization: Bearer $TOKEN" \
    -d '{ "gracePeriod": 300, "message": "Neustart in 5 Minuten für Updates" }'

# Gerät sperren (z.B. gestohlener Laptop)
curl -X POST http://localhost:8080/api/devices/DEVICE-ID/actions/lock \
    -H "Authorization: Bearer $TOKEN" \
    -d '{ "message": "Dieses Gerät wurde gesperrt. Kontakt: IT-Abteilung" }'

# BitLocker-Key rotieren
curl -X POST http://localhost:8080/api/devices/DEVICE-ID/actions/rotate-key \
    -H "Authorization: Bearer $TOKEN" \
    -d '{ "keyType": "bitlocker" }'
```

### Drucker einrichten

```bash
# Netzwerk-Drucker hinzufügen
curl -X POST http://localhost:8080/api/printers \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Büro-Drucker",
        "address": "192.168.1.100",
        "driver": "auto",
        "shared": true,
        "targets": { "all": true }
    }'
```

---

## Ressourcenverbrauch (Lite-Modus)

| Service | RAM (Limit) | Funktion |
|---------|-------------|----------|
| PostgreSQL | 512 MB | Alle Datenbanken |
| Redis | 192 MB | Cache & Sessions |
| MongoDB | 512 MB | Gerätedaten |
| LLDAP | 128 MB | User-Verzeichnis |
| Identity Service | 256 MB | User-Management |
| Auth Service | 256 MB | Authentifizierung |
| Device Service | 256 MB | Geräte-Management |
| Policy Service | 256 MB | Policy-Engine |
| Network Infra | 256 MB | DNS/DHCP/SMB |
| API Gateway | 256 MB | Routing |
| API Backend | 256 MB | REST-API |
| Web App | 512 MB | Frontend |
| **Gesamt** | **~3.6 GB** | **Alle Core-Features** |

Empfehlung: Server mit 8 GB RAM, 4 CPU-Cores, 50 GB SSD.

---

## Upgrade auf Full-Modus

Wenn du mehr Enterprise-Features brauchst:

```bash
# Alle Enterprise-Services zusätzlich starten
docker-compose -f docker-compose.yml up -d

# Oder nur einzelne Services nachinstallieren
docker-compose -f docker-compose.yml up -d security-scanner grafana prometheus
```

---

## Troubleshooting

```bash
# Service-Status prüfen
docker-compose -f docker-compose.lite.yml ps

# Logs eines Services anzeigen
docker-compose -f docker-compose.lite.yml logs -f device-service

# Alle Logs
docker-compose -f docker-compose.lite.yml logs -f --tail=100

# Service neustarten
docker-compose -f docker-compose.lite.yml restart api-backend

# Alles neu bauen
docker-compose -f docker-compose.lite.yml up -d --build

# Datenbank-Reset (ACHTUNG: löscht alle Daten!)
docker-compose -f docker-compose.lite.yml down -v
./quick-setup.sh --lite
```
