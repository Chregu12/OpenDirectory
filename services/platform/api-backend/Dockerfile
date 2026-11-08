FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

# Copy application code
# NOTE: server.js requires ./utils/serviceClient (device-service delegation
# client) and ./db (Postgres persistence for users/devices/enrollment
# tokens/setup config, with migrations/*.sql run at boot) — both must be
# copied too, or the container crashes on boot with "Cannot find module
# './utils/serviceClient'" / "./db". __tests__ is intentionally NOT copied
# — dev/test-only, not needed at runtime.
COPY server.js db.js ./
COPY utils ./utils/
COPY migrations ./migrations/

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
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/health',{headers:{Origin:(process.env.CORS_ORIGIN||'http://localhost:3000').split(',')[0].trim()},signal:AbortSignal.timeout(5000)}).then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))"

# Start the application
CMD ["node", "server.js"]
