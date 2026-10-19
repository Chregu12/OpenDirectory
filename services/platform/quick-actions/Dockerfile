FROM node:22-alpine

WORKDIR /app/services/platform/quick-actions
COPY services/platform/quick-actions/package.json ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund
COPY services/platform/quick-actions/src/ ./src/
COPY packages/oidc-access-state.js /app/packages/oidc-access-state.js
COPY packages/identity-authorization-contract.js /app/packages/identity-authorization-contract.js

USER node
EXPOSE 3950
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:3950/health').then(response=>process.exit(response.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/index.js"]
