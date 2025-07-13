FROM node:18-alpine
WORKDIR /app
COPY package*.json .
RUN npm install
RUN mkdir -p /app/uploads/citizenship_images
COPY . .
RUN chmod +x wait-for-it.sh
EXPOSE 3000
ENV DB_NAME=evoting
COPY init-db.sh ./init-db.sh
RUN chmod +x init-db.sh
CMD ["./wait-for-it.sh", "db:5432", "--", "node", "server.js"]
