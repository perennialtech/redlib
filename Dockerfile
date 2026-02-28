FROM rust:trixie AS builder

WORKDIR /redlib


RUN apt update && apt install -y cmake clang clang-tools
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
FROM gcr.io/distroless/cc-debian13:nonroot AS release

# Import redlib binary from builder
COPY --from=builder /redlib/target/release/redlib ./redlib
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblzma.so.5 /usr/lib/liblzma.so.5

# Document that we intend to expose port 8080
EXPOSE 8080

# Arti
ENV REDLIB_ARTI_PATH="/tmp/arti"
VOLUME ["/tmp/arti"]

CMD ["./redlib"]
