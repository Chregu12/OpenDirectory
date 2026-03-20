FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Remove dev dependencies after build
RUN npm prune --production --legacy-peer-deps

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S integration -u 1001

# Change ownership of the app directory
RUN chown -R integration:nodejs /app
USER integration

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

EXPOSE 3005

CMD ["npm", "start"]