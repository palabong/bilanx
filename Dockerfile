# syntax=docker/dockerfile:1
FROM node:22-slim AS builder

WORKDIR /app

# Copy package manifests first for better Docker layer caching
COPY package*.json ./

# Use npm install instead of npm ci so the lockfile can be reconciled during build
# and avoid the lockfile drift that breaks Fly deploys.
RUN npm install --include=dev

# Copy application source and build the production bundle
COPY . .
RUN npm run build

FROM node:22-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy runtime dependencies and built output
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/server.cjs"]
