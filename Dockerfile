# Builder stage
FROM --platform=$BUILDPLATFORM rust:bookworm as builder

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Install SQLx CLI for migrations
RUN cargo install sqlx-cli --no-default-features --features sqlite

# Copy only the dependency files first
COPY Cargo.toml Cargo.lock ./

# Create dummy database for SQLx compile-time checks
RUN mkdir -p /app/data && \
    touch /app/data/password_manager.db

# Set DATABASE_URL for SQLx compile-time checks
ENV DATABASE_URL=sqlite:///app/data/password_manager.db

# Copy migrations and run them
COPY migrations ./migrations
RUN sqlx database create && \
    sqlx migrate run

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY . .

# Build the application with cross-compilation support
RUN rustup target add aarch64-unknown-linux-gnu && \
    cargo build --release --target aarch64-unknown-linux-gnu

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser

WORKDIR /app

# Copy the binary and SQLx CLI from builder
COPY --from=builder /usr/src/app/target/aarch64-unknown-linux-gnu/release/password-manager-api /app/password-manager-api
COPY --from=builder /usr/local/cargo/bin/sqlx /app/sqlx
# Copy migrations folder
COPY --from=builder /usr/src/app/migrations /app/migrations
# Copy entrypoint script
COPY docker-entrypoint.sh /app/

# Create a directory for the SQLite database and set permissions
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app && \
    chmod 755 /app/password-manager-api && \
    chmod 755 /app/sqlx && \
    chmod 755 /app/docker-entrypoint.sh

# Switch to non-root user
USER appuser

# Set environment variables
ENV RUST_LOG=info
ENV DATABASE_URL=sqlite:///app/data/password_manager.db

EXPOSE 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["./password-manager-api"] 