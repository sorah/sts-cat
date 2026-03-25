FROM public.ecr.aws/docker/library/rust:1-slim-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release --bin sts-cat-http

FROM public.ecr.aws/docker/library/debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/sts-cat-http /usr/local/bin/sts-cat-http

CMD ["sts-cat-http"]
