FROM rust:slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    perl \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /redlib

# download (most) dependencies in their own layer
COPY Cargo.lock Cargo.toml ./
RUN mkdir src && echo "fn main() { panic!(\"why am i running?\") }" > src/main.rs
RUN cargo build --release --locked --bin redlib
RUN rm ./src/main.rs && rmdir ./src

# copy the source and build the redlib binary
COPY . ./
# Update the mtime of the main file to force a rebuild of the binary
RUN touch src/main.rs
RUN cargo build --release --locked --bin redlib
RUN echo "finished building redlib!"

########################
## release image
########################
FROM gcr.io/distroless/cc-debian13 AS release

# Import redlib binary from builder
COPY --from=builder /redlib/target/release/redlib /app/redlib

# Use non-root user provided by distroless
USER nonroot:nonroot

# Document that we intend to expose port 8080
EXPOSE 8080

CMD ["/app/redlib"]
