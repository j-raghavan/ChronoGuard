# ChronoGuard Dashboard - Minimal UI for policy windows, denials, and audit integrity
FROM node:18-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY frontend/src/ ./src/
COPY frontend/public/ ./public/
COPY frontend/next.config.js ./
COPY frontend/tsconfig.json ./
COPY frontend/tailwind.config.js ./

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine as production

# Install curl for health checks
RUN apk add --no-cache curl

# Create application user
RUN addgroup -g 1000 chronoguard \
    && adduser -u 1000 -G chronoguard -s /bin/sh -D chronoguard

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=chronoguard:chronoguard /app/.next ./.next
COPY --from=builder --chown=chronoguard:chronoguard /app/public ./public
COPY --from=builder --chown=chronoguard:chronoguard /app/package*.json ./
COPY --from=builder --chown=chronoguard:chronoguard /app/next.config.js ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Switch to application user
USER chronoguard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Expose port
EXPOSE 3000

# Labels
LABEL org.opencontainers.image.title="ChronoGuard Dashboard"
LABEL org.opencontainers.image.description="Minimal UI to visualize policy windows, denials, and audit integrity"
LABEL org.opencontainers.image.vendor="ChronoGuard"
LABEL org.opencontainers.image.version="1.0.0"

# Start Next.js application
CMD ["npm", "start"]