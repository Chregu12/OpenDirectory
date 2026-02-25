FROM node:18-alpine

# Install required system packages for network services
RUN apk add --no-cache \
    bind \
    bind-tools \
    dhcp \
    samba \
    samba-common-tools \
    nfs-utils \
    iproute2 \
    net-tools \
    tcpdump \
    nmap \
    sudo \
    dumb-init

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /etc/bind /etc/dhcp /etc/samba /srv/shares /var/log/network

# Create network user for service isolation
RUN addgroup -S network && adduser -S -G network network

# Set proper permissions
RUN chown -R network:network /app
RUN chmod +x /app/scripts/*.sh || true

# Expose application port
EXPOSE 3007

# Use dumb-init as PID 1
ENTRYPOINT ["dumb-init", "--"]

# Switch to network user for application
USER network

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3007/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

# Start the application
CMD ["node", "src/index.js"]