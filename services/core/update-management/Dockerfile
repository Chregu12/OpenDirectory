# OpenDirectory Update Management Service
FROM node:18-alpine AS base

# Set working directory
WORKDIR /app

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
        curl \
        dumb-init \
        && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opendirectory -u 1001

# Copy package files
COPY package*.json ./
COPY --chown=opendirectory:nodejs package*.json ./

# Install dependencies
FROM base AS deps
RUN npm ci --only=production && npm cache clean --force

# Development stage
FROM base AS dev
RUN npm ci
COPY --chown=opendirectory:nodejs . .
USER opendirectory
EXPOSE 3000
CMD ["dumb-init", "npm", "run", "dev"]

# Production build
FROM base AS build
RUN npm ci
COPY . .
RUN npm run build 2>/dev/null || echo "No build step defined"

# Production stage
FROM base AS production

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy application code
COPY --chown=opendirectory:nodejs ./src ./src
COPY --chown=opendirectory:nodejs ./package*.json ./

# Create necessary directories
RUN mkdir -p /app/logs /app/storage && \
    chown -R opendirectory:nodejs /app/logs /app/storage

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Set user and security context
USER opendirectory

# Expose port
EXPOSE 3000

# Set environment
ENV NODE_ENV=production \
    PORT=3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "src/index.js"]

# Add labels for metadata
LABEL maintainer="OpenDirectory Team <team@opendirectory.local>" \
      version="1.0.0" \
      description="OpenDirectory Update Management Service" \
      org.opencontainers.image.title="OpenDirectory Update Management" \
      org.opencontainers.image.description="Comprehensive update management and remote device actions for OpenDirectory platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="OpenDirectory" \
      org.opencontainers.image.licenses="MIT"