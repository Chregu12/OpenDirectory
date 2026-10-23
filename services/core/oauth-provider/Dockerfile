FROM node:20-alpine

WORKDIR /app

COPY services/core/oauth-provider/package.json ./
RUN npm install --omit=dev --ignore-scripts

COPY services/core/oauth-provider/src/ ./src/
COPY services/core/oauth-provider/migrations/ ./migrations/
COPY services/core/oauth-provider/scripts/signing-keys.js ./scripts/signing-keys.js
COPY services/core/oauth-provider/scripts/mfa-key.js ./scripts/mfa-key.js
COPY services/core/oauth-provider/scripts/bootstrap-application-access.js ./scripts/bootstrap-application-access.js
COPY packages/grpc-event-bus/ /packages/grpc-event-bus/
COPY packages/identity-authorization-contract.js /packages/identity-authorization-contract.js
COPY packages/credential-authorization-contract.js /packages/credential-authorization-contract.js
COPY packages/employee-invitation-contract.js /packages/employee-invitation-contract.js
COPY packages/tenant-authorization-contract.js /packages/tenant-authorization-contract.js
COPY packages/company-app-contract.js /packages/company-app-contract.js
COPY packages/mfa-authorization-contract.js /packages/mfa-authorization-contract.js
COPY packages/role-authentication-contract.js /packages/role-authentication-contract.js
COPY packages/policy-authorization-contract.js /packages/policy-authorization-contract.js
COPY packages/policy-command-contract.js /packages/policy-command-contract.js
COPY packages/directory-role-contract.js /packages/directory-role-contract.js
COPY packages/company-registration-contract/ /packages/company-registration-contract/
COPY packages/organization-profile-contract/ /packages/organization-profile-contract/
RUN cd /packages/grpc-event-bus && npm install --omit=dev --ignore-scripts --no-audit --no-fund

USER node

EXPOSE 3010

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3010/health', response => process.exit(response.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "src/index.js"]
