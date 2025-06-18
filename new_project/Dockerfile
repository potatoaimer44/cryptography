# Use Node.js 18 as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json .
RUN npm install --legacy-peer-deps

# Copy all source files
COPY . .

# Build the React frontend
RUN npm run build

# Expose port for the server
EXPOSE 3001

# Start the server
CMD ["node", "server.js"]
