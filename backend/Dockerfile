# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies and tidy
RUN go mod download && go mod tidy

# Copy source code
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/backend

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /app

# Copy binary and config from builder
COPY --from=builder /app/backend /app/backend
COPY --from=builder /app/config/config.yaml /app/config/config.yaml

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set environment variables
ENV TZ=UTC

# Expose API port
EXPOSE 8080

# Set security-related environment variables
ENV GODEBUG=netdns=go
ENV GOTRACEBACK=0

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/backend"] 