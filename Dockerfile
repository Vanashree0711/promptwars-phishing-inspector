# ============================================================
# Fake Offer Letter & Phishing Inspector — Dockerfile
# Designed for Google Cloud Run deployment
# ============================================================

FROM node:24-alpine AS base

# Set working directory
WORKDIR /app

# Copy package files and install production dependencies only
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy application source
COPY . .

# Set production environment
ENV NODE_ENV=production
ENV PORT=8080

# Expose Cloud Run's expected port
EXPOSE 8080

# Run as non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001 -G nodejs
USER nodeuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# Start the server
CMD ["node", "server.js"]
