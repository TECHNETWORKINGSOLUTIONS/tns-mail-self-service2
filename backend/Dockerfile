FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --legacy-peer-deps
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
