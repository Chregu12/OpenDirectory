# OpenDirectory DNS Setup

## Hosts File Configuration

Add these entries to your `/etc/hosts` file (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
# OpenDirectory Services
192.168.1.223   mdm.opendirectory.local
192.168.1.223   console.opendirectory.local
192.168.1.223   users.opendirectory.local
192.168.1.223   monitoring.opendirectory.local
192.168.1.223   metrics.opendirectory.local
192.168.1.223   vault.opendirectory.local
```

## Access URLs

### Main Console
- **Primary:** http://mdm.opendirectory.local
- **Alternative:** http://console.opendirectory.local
- **Direct IP:** http://192.168.1.223 (fallback)

### Individual Services
- **User Directory:** http://users.opendirectory.local (LLDAP)
- **Monitoring:** http://monitoring.opendirectory.local (Grafana)
- **Metrics:** http://metrics.opendirectory.local (Prometheus)
- **Secrets:** http://vault.opendirectory.local (Vault)

### Client Installation
All installation scripts available through any of the console URLs:
- Windows: `powershell -c "irm http://mdm.opendirectory.local/install.ps1 | iex"`
- macOS/Linux: `curl -s http://mdm.opendirectory.local/install.sh | sudo bash`

## DNS Server Configuration (Optional)

For automatic DNS resolution across your network, configure your DNS server with these A records:

```
mdm.opendirectory.local.        A    192.168.1.223
console.opendirectory.local.    A    192.168.1.223
users.opendirectory.local.      A    192.168.1.223
monitoring.opendirectory.local. A    192.168.1.223
metrics.opendirectory.local.    A    192.168.1.223
vault.opendirectory.local.      A    192.168.1.223
```

## Service Status

All services are now accessible through the Traefik ingress controller at `192.168.1.223`.