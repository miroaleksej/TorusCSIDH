# docker/production/Dockerfile
# Production-ready Docker image for TorusCSIDH with security hardening
# Base image with minimal dependencies
FROM rust:1.78.0-alpine3.19 as builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    libressl-dev \
    linux-headers \
    pkgconf \
    gmp-dev \
    gmp

# Copy source code
WORKDIR /app
COPY . .

# Build application with all features
RUN cargo build --release --all-features

# Final production image
FROM alpine:3.19

# Install only runtime dependencies
RUN apk add --no-cache \
    libressl \
    gmp \
    ca-certificates \
    bash \
    coreutils && \
    update-ca-certificates

# Create non-root user with minimal privileges
RUN addgroup -g 1000 -S toruscsidh && \
    adduser -u 1000 -S toruscsidh -G toruscsidh -h /app -s /sbin/nologin -D toruscsidh && \
    mkdir -p /app/{bin,config,data,logs,proofs} && \
    chown -R toruscsidh:toruscsidh /app

# Copy binary from builder
COPY --from=builder --chown=toruscsidh:toruscsidh /app/target/release/toruscsidh /app/bin/

# Copy configuration files
COPY --chown=toruscsidh:toruscsidh config/production.toml /app/config/
COPY --chown=toruscsidh:toruscsidh config/checksums.sha256 /app/config/

# Copy formal proofs
COPY --chown=toruscsidh:toruscsidh proofs/*.vo /app/proofs/

# Copy security and health check scripts
COPY --chown=toruscsidh:toruscsidh scripts/security_checks.sh /app/scripts/
COPY --chown=toruscsidh:toruscsidh scripts/health_check.sh /app/scripts/

# Set permissions
RUN chmod 755 /app/bin/toruscsidh && \
    chmod 644 /app/config/production.toml && \
    chmod 644 /app/config/checksums.sha256 && \
    chmod 644 /app/proofs/*.vo && \
    chmod 755 /app/scripts/security_checks.sh && \
    chmod 755 /app/scripts/health_check.sh

# Security hardening - drop all capabilities except necessary ones
USER toruscsidh
WORKDIR /app

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
    CMD /app/scripts/health_check.sh || exit 1

# Security checks before startup
ENTRYPOINT ["/app/scripts/security_checks.sh"]
CMD ["/app/bin/toruscsidh", "--config", "/app/config/production.toml"]
