FROM node:18-alpine

# Install CUPS, SANE, and other printing dependencies
RUN apk add --no-cache \
    cups \
    cups-client \
    cups-filters \
    cups-pdf \
    ghostscript \
    sane \
    sane-backends \
    imagemagick \
    tesseract-ocr \
    tesseract-ocr-data-eng \
    avahi \
    avahi-tools \
    mdns-scan \
    net-snmp-tools \
    openssl \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /var/spool/cups /var/cache/cups /var/log/cups /etc/cups/ssl /var/scans

# Configure CUPS
RUN echo "ServerName printer-service" > /etc/cups/client.conf && \
    echo "Listen *:631" >> /etc/cups/cupsd.conf && \
    echo "WebInterface Yes" >> /etc/cups/cupsd.conf && \
    echo "DefaultEncryption Never" >> /etc/cups/cupsd.conf

# Set permissions
RUN chmod 755 /var/spool/cups && \
    chmod 755 /var/cache/cups && \
    chmod 755 /var/log/cups

# Expose ports
EXPOSE 3006 631

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s \
  CMD node -e "require('http').get('http://localhost:3006/health', (r) => {r.statusCode === 200 ? process.exit(0) : process.exit(1)})"

# Start script
COPY <<'EOF' /app/start.sh
#!/bin/sh
# Start CUPS in background
cupsd

# Start Avahi for mDNS discovery
avahi-daemon --no-drop-root --no-rlimits -D

# Wait for services
sleep 5

# Start Node.js application
exec node src/index.js
EOF

RUN chmod +x /app/start.sh

# Run as root (required for CUPS)
USER root

CMD ["/app/start.sh"]