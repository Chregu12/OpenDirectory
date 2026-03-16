FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE ${PORT:-3908}
CMD ["node", "src/index.js"]
