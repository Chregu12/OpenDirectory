FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE ${PORT:-3900}
CMD ["node", "src/index.js"]
