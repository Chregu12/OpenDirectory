FROM node:18-alpine

LABEL maintainer="OpenDirectory Team"
LABEL description="Enterprise App Store with domain-aware catalog and push installation"

RUN apk add --no-cache tini curl

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production && npm cache clean --force

COPY . .

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
