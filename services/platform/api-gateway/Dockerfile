FROM node:18-alpine

# Install security updates and necessary packages
RUN apk update && apk upgrade && apk add --no-cache \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S gateway -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY src/ ./src/
COPY config/ ./config/ 2>/dev/null || true

# Create logs directory
RUN mkdir -p logs && chown -R gateway:nodejs logs

# Set proper permissions
RUN chown -R gateway:nodejs /app

# Switch to non-root user
USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${API_GATEWAY_PORT:-3000}/health || exit 1

# Expose ports
EXPOSE 3000 3001

# Start the application
CMD ["node", "src/index.js"]