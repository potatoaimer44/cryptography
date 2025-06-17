FROM node:18  # Changed from alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "--trace-uncaught", "server.js"]
