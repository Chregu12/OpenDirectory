FROM node:20-alpine

WORKDIR /app

# Integration service URL is used server-side in next.config.js rewrites at build time.
# It points to the k8s cluster-internal service - never exposed to the browser.
ARG INTEGRATION_SERVICE_URL=http://working-integration-service:3005
ENV INTEGRATION_SERVICE_URL=$INTEGRATION_SERVICE_URL

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app/.next

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV NODE_ENV production

CMD ["npm", "start"]