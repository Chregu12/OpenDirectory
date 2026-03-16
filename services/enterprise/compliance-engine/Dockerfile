FROM node:18-alpine

RUN apk add --no-cache tini

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

USER appuser

EXPOSE 3907

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/index.js"]
