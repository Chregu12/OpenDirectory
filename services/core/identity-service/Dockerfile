FROM node:18-alpine

RUN apk add --no-cache dumb-init

WORKDIR /app

COPY services/core/identity-service/package*.json ./

RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

COPY services/core/identity-service/ ./
COPY packages/organization-profile-contract/ /packages/organization-profile-contract/
COPY packages/company-registration-contract/ /packages/company-registration-contract/
COPY packages/device-inventory-contract/ /packages/device-inventory-contract/
COPY packages/company-license-contract/ /packages/company-license-contract/
COPY packages/company-automation-contract.js /packages/company-automation-contract.js
COPY packages/company-license-automation-contract.js /packages/company-license-automation-contract.js
COPY packages/company-group-rule-contract.js /packages/company-group-rule-contract.js
COPY packages/company-blueprint-contract/ /packages/company-blueprint-contract/
COPY packages/company-blueprint-assignment-contract/ /packages/company-blueprint-assignment-contract/
COPY packages/tenant-authorization-contract.js /packages/tenant-authorization-contract.js
COPY packages/oidc-tenant-state.js /packages/oidc-tenant-state.js
COPY packages/oidc-access-state.js /packages/oidc-access-state.js
COPY packages/identity-authorization-contract.js /packages/identity-authorization-contract.js
COPY packages/mfa-authorization-contract.js /packages/mfa-authorization-contract.js
COPY packages/role-authentication-contract.js /packages/role-authentication-contract.js
COPY packages/directory-role-contract.js /packages/directory-role-contract.js
COPY packages/group-license-lease-contract.js /packages/group-license-lease-contract.js
COPY packages/grpc-event-bus/ /packages/grpc-event-bus/
RUN cd /packages/grpc-event-bus && npm install --omit=dev --ignore-scripts --no-audit --no-fund

RUN addgroup -S appuser && adduser -S -G appuser appuser
RUN chown -R appuser:appuser /app

EXPOSE 3001

ENTRYPOINT ["dumb-init", "--"]

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

CMD ["node", "src/index.js"]
