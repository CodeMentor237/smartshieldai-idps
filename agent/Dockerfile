# Build stage
FROM golang:1.20-alpine AS builder

# Install build dependencies
# Add any necessary signing tools here, e.g., gnupg for GPG signing on Linux
RUN apk add --no-cache git gcc musl-dev gnupg

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/agent

# Placeholder for Agent Binary Signing (Linux example using GPG)
# You will need to:
# 1. Ensure your GPG key is imported into the build environment.
# 2. Securely provide the passphrase for the GPG key.
# 3. Adjust the command according to your GPG key and desired output (detached signature, etc.)
# RUN gpg --batch --yes --pinentry-mode loopback --passphrase "YOUR_GPG_PASSPHRASE" --detach-sign --armor /app/agent
# RUN echo "Agent binary signing placeholder. Replace with actual signing commands." 

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/agent /app/agent

# Copy configuration
COPY --from=builder /app/config/config.yaml /app/config/config.yaml

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set environment variables
ENV TZ=UTC

# Expose health check port
EXPOSE 8081

# Set security-related environment variables
ENV GODEBUG=netdns=go
ENV GOTRACEBACK=0

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

# Run the application
ENTRYPOINT ["/app/agent"] 