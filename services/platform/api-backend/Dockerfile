FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

# Copy application code
# NOTE: server.js requires ./utils/serviceClient (device-service delegation
# client) — it must be copied too, or the container crashes on boot with
# "Cannot find module './utils/serviceClient'". __tests__ is intentionally
# NOT copied — dev/test-only, not needed at runtime.
COPY server.js ./
COPY utils ./utils/

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opendirectory -u 1001

# Change ownership
RUN chown -R opendirectory:nodejs /app
USER opendirectory

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-8080}/api/health || exit 1

# Start the application
CMD ["node", "server.js"]