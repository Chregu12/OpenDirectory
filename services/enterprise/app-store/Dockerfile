FROM node:20-alpine

LABEL maintainer="OpenDirectory Team"
LABEL description="Enterprise App Store with domain-aware catalog and push installation"

RUN apk add --no-cache tini curl samba-client

WORKDIR /app

COPY services/enterprise/app-store/package*.json ./

RUN npm ci --omit=dev --legacy-peer-deps && npm cache clean --force

COPY services/enterprise/app-store/src/ ./src/
COPY packages/oidc-access-state.js /packages/oidc-access-state.js
COPY packages/grpc-event-bus/ /packages/grpc-event-bus/
RUN cd /packages/grpc-event-bus && npm install --omit=dev --ignore-scripts --no-audit --no-fund

RUN addgroup -g 1001 -S appstore && \
    adduser -S appstore -u 1001 -G appstore

RUN mkdir -p /app/uploads /app/logs && \
    chown -R appstore:appstore /app

USER appstore

EXPOSE 3906

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3906/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/index.js"]
