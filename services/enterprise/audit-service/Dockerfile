FROM node:18-alpine

RUN apk add --no-cache tini

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production --legacy-peer-deps

COPY . .

RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

USER appuser

EXPOSE 3908

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3908/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/index.js"]
