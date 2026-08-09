FROM rust:1.88.0-bookworm AS build
WORKDIR /runner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:12.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=build /runner/target/release/mail-differential-runner /usr/local/bin/differential-runner
ENTRYPOINT ["differential-runner"]
