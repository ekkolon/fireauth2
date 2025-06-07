# (todo): Use Rust image with less vulnerabilities
FROM rust:1.82 AS builder

WORKDIR /usr/src/app
COPY . /usr/src/app 

# Build and cache release binary and dependent crates
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:1.82,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build --release && mv ./target/release/fireauth2 ./fireauth2

# Debian-based 'distroless' runtime image
FROM gcr.io/distroless/cc-debian12

# We need this env variable to point the Actix web server to the right host
ENV DOCKER_RUNNING=true

WORKDIR /app

# Copy compiled binary from builder's cargo install directory
COPY --from=builder /usr/src/app/fireauth2 ./fireauth2

# set user to non-root unless root is required for your app
USER 1001

CMD ["./fireauth2"]