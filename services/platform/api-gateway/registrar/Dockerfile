FROM node:18-alpine

# Install necessary packages
RUN apk update && apk add --no-cache curl bash

# Create app directory
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S registrar -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY index.js ./

# Set proper permissions
RUN chown -R registrar:nodejs /app

# Switch to non-root user
USER registrar

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ps aux | grep -v grep | grep node || exit 1

# Start the application
CMD ["node", "index.js"]