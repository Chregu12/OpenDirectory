FROM node:20-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY package.json ./
RUN npm install --production && npm install winston-daily-rotate-file joi
COPY . .
EXPOSE ${PORT:-3900}
CMD ["node", "src/index.js"]
