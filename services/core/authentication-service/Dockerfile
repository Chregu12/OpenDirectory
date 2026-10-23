FROM node:18-alpine

RUN apk add --no-cache dumb-init

WORKDIR /app

COPY services/core/authentication-service/package*.json ./

RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

COPY services/core/authentication-service/ ./
COPY packages/employee-invitation-contract.js /packages/employee-invitation-contract.js
COPY packages/credential-authorization-contract.js /packages/credential-authorization-contract.js
COPY packages/employee-invitation-request.js /packages/employee-invitation-request.js
COPY packages/identity-authorization-contract.js /packages/identity-authorization-contract.js
COPY packages/tenant-authorization-contract.js /packages/tenant-authorization-contract.js

RUN addgroup -S appuser && adduser -S -G appuser appuser
RUN chown -R appuser:appuser /app

EXPOSE 3002

ENTRYPOINT ["dumb-init", "--"]

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3002/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

CMD ["node", "src/index.js"]
