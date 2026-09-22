# Use Node.js base image
FROM node:20-slim AS builder

WORKDIR /app

# Copy package management files
COPY package*.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy the rest of the source code
COPY . .

# Build the frontend and backend Express server
RUN npm run build

# Use a clean, smaller runtime image
FROM node:20-slim

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000

# Copy package files and build output
COPY package*.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

# Expose server port
EXPOSE 3000

# Start Express server
CMD ["node", "dist/server.cjs"]
