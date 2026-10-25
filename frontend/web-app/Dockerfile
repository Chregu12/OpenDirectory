FROM node:20-alpine

WORKDIR /app/frontend/web-app

# Next.js stores rewrite destinations in the production build manifest, so
# these URLs must point to the cluster services at image-build time.
# Override them when building for a differently named Helm release.
ARG INTEGRATION_SERVICE_URL=http://opendirectory-integration-service:3005
ARG AUTH_SERVICE_URL=http://opendirectory-auth-service:3002
ARG IDENTITY_SERVICE_URL=http://opendirectory-identity-service:3001
ARG API_BACKEND_URL=http://opendirectory-api-backend:8080
ARG DEVICE_SERVICE_URL=http://opendirectory-device-service:3003
ARG POLICY_SERVICE_URL=http://opendirectory-policy-service:3004
ARG LICENSE_ADAPTER_URL=http://opendirectory-license-management:3018
ARG CORE_GATEWAY_URL=http://opendirectory-api-gateway:3000
ARG OAUTH_PROVIDER_URL=http://opendirectory-oauth-provider:3010
ENV INTEGRATION_SERVICE_URL=${INTEGRATION_SERVICE_URL}
ENV AUTH_SERVICE_URL=${AUTH_SERVICE_URL}
ENV IDENTITY_SERVICE_URL=${IDENTITY_SERVICE_URL}
ENV API_BACKEND_URL=${API_BACKEND_URL}
ENV DEVICE_SERVICE_URL=${DEVICE_SERVICE_URL}
ENV POLICY_SERVICE_URL=${POLICY_SERVICE_URL}
ENV LICENSE_ADAPTER_URL=${LICENSE_ADAPTER_URL}
ENV CORE_GATEWAY_URL=${CORE_GATEWAY_URL}
ENV OAUTH_PROVIDER_URL=${OAUTH_PROVIDER_URL}

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
