FROM node:18-alpine

RUN apk add --no-cache dumb-init

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production --legacy-peer-deps && npm cache clean --force

COPY . .

RUN addgroup -S appuser && adduser -S -G appuser appuser
RUN chown -R appuser:appuser /app

EXPOSE 3011

ENTRYPOINT ["dumb-init", "--"]

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3011/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

CMD ["node", "src/index.js"]
