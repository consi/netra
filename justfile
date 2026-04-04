set dotenv-load

default: build

# Install all dependencies
setup:
    cd frontend && pnpm install

# Build frontend then Rust binary
build: build-frontend
    cargo build --release

# Build frontend only
build-frontend:
    cd frontend && pnpm run build

# Run Rust backend in dev mode
dev-backend:
    RUST_LOG=debug cargo run

# Run Vite frontend dev server
dev-frontend:
    cd frontend && pnpm run dev

# Run all tests
test: test-backend test-frontend

test-backend:
    cargo test

test-frontend:
    cd frontend && pnpm run lint && pnpm run test

# Lint everything
lint: lint-backend lint-frontend

lint-backend:
    cargo clippy -- -D warnings

lint-frontend:
    cd frontend && pnpm run lint

# Format everything
format: format-backend format-frontend

format-backend:
    cargo fmt

format-frontend:
    cd frontend && pnpm run format

# Check formatting (CI)
format-check:
    cargo fmt -- --check
    cd frontend && pnpm run format:check

# Full check (CI equivalent)
check: format-check lint test build
