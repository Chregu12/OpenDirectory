FROM node:18-alpine

# Install system dependencies for Kerberos, LDAP, and PKI
RUN apk add --no-cache \
    krb5-dev \
    openldap-dev \
    openssl-dev \
    python3 \
    make \
    g++ \
    git \
    bind-tools \
    curl \
    ca-certificates

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data/certs \
    /app/data/keys \
    /app/data/policies \
    /app/data/logs \
    /app/data/cache \
    /app/data/kerberos \
    /app/data/ldap

# Set permissions
RUN chown -R node:node /app

# Switch to non-root user
USER node

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3008/health || exit 1

# Expose ports
EXPOSE 3008 389 636 88 464 53 443 80

# Start the service
CMD ["npm", "start"]