FROM node:18-alpine

# Install dependencies
RUN apk add --no-cache netcat-openbsd

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# Make script executable
RUN chmod +x wait-for-it.sh

CMD ["sh", "-c", "./wait-for-it.sh db 5432 && node app.js"]
