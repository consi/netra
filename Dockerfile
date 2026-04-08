FROM rust:1.94-trixie AS builder

# Install musl toolchain, Node.js and pnpm for frontend build
RUN apt-get update && \
    apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    corepack enable && \
    corepack prepare pnpm@latest --activate

WORKDIR /app
COPY . .

# Build frontend
RUN cd frontend && pnpm install --frozen-lockfile && pnpm run build

# Build static Rust binary
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/netra /netra
EXPOSE 1337/tcp
EXPOSE 2055/udp
ENTRYPOINT ["/netra"]
