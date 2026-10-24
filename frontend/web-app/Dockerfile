FROM node:20-alpine

WORKDIR /app/frontend/web-app

# Integration service URL is used server-side in next.config.js rewrites at build time.
# It points to the k8s cluster-internal service - never exposed to the browser.
ARG INTEGRATION_SERVICE_URL=http://integration-service:4000
ENV INTEGRATION_SERVICE_URL=${INTEGRATION_SERVICE_URL}

# Copy package files
COPY frontend/web-app/package.json frontend/web-app/package-lock.json ./

# Install dependencies
RUN npm ci --legacy-peer-deps

# Copy source code
COPY frontend/web-app/ .
COPY packages/organization-profile-contract/ /app/packages/organization-profile-contract/
COPY packages/company-registration-contract/ /app/packages/company-registration-contract/
COPY packages/employee-invitation-contract.js /app/packages/employee-invitation-contract.js
COPY packages/identity-authorization-contract.js /app/packages/identity-authorization-contract.js
COPY packages/tenant-authorization-contract.js /app/packages/tenant-authorization-contract.js
COPY packages/directory-role-contract.js /app/packages/directory-role-contract.js

# Build the application
RUN npm run build
RUN npm prune --omit=dev --legacy-peer-deps

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app/frontend/web-app/.next

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["npm", "start"]
