FROM rust:1.85-trixie AS builder

# Install Node.js and pnpm for frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    corepack enable && \
    corepack prepare pnpm@latest --activate

WORKDIR /app
COPY . .

# Build frontend
RUN cd frontend && pnpm install --frozen-lockfile && pnpm run build

# Build Rust binary
RUN cargo build --release

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /app/target/release/netra /netra
EXPOSE 1337/tcp
EXPOSE 2055/udp
USER nonroot
ENTRYPOINT ["/netra"]
