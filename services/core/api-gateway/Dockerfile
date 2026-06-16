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
RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

# Copy application code
COPY src/ ./src/

# Create logs directory
RUN mkdir -p logs && chown -R gateway:nodejs logs

# Set proper permissions
RUN chown -R gateway:nodejs /app

# Switch to non-root user
USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Expose port
EXPOSE 8080

# Start the application
CMD ["node", "src/index.js"]
