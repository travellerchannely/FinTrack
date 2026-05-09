FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_DIR=/app/db

RUN mkdir -p /app/db

EXPOSE 3000

CMD ["node", "server.js"]
