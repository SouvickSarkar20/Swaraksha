# ==========================================
# STAGE 1: Builder (Compiles TypeScript)
# ==========================================
FROM node:20-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and lock file first to leverage Docker layer caching
COPY package.json package-lock.json ./

# Install ALL dependencies (including devDependencies like typescript)
RUN npm ci

# Copy the rest of the application code
# (This respects the .dockerignore file, so node_modules and .env are excluded)
COPY . .

# Compile TypeScript to JavaScript (outputs to /dist folder)
RUN npm run build


# ==========================================
# STAGE 2: Runner (Production Environment)
# ==========================================
FROM node:20-alpine AS runner

# Set production environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Create a non-root user and group for security
# Running apps as 'root' in Docker is a massive security risk
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory
WORKDIR /app

# Copy package files again
COPY package.json package-lock.json ./

# Install ONLY production dependencies (--omit=dev)
# This keeps the image size tiny and removes vulnerable dev tools from production
RUN npm ci --omit=dev

# Copy the compiled /dist folder from the Builder stage
COPY --from=builder /app/dist ./dist

# Change ownership of the /app directory to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose the port the Fastify server will run on
EXPOSE 3000

# Start the application
CMD ["node", "dist/server.js"]
