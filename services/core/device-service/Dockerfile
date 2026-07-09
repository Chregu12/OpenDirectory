FROM node:18-alpine

RUN apk add --no-cache dumb-init

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

COPY . .

RUN addgroup -S appuser && adduser -S -G appuser appuser
RUN chown -R appuser:appuser /app

# Driver/hardware-report storage (FileDriverRepository / FileHardwareReportRepository
# default paths). These are meant to be mounted as named volumes in
# docker-compose so data survives container recreation; named volumes are
# created root-owned by default, so pre-create + chown them here for appuser
# (below) to be able to write into the mounted paths.
RUN mkdir -p /var/lib/opendirectory/device-drivers /var/lib/opendirectory/device-hardware && \
    chown -R appuser:appuser /var/lib/opendirectory

EXPOSE 3003

ENTRYPOINT ["dumb-init", "--"]

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3003/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

CMD ["node", "src/index.js"]
