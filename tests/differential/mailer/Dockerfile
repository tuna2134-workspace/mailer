FROM rust:1.88.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p maild -p mail-migrate -p mail-queue-worker

FROM debian:12.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd openssl postgresql-client procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/maild /usr/local/bin/maild
COPY --from=build /src/target/release/mail-migrate /usr/local/bin/mail-migrate
COPY --from=build /src/target/release/mail-queue-worker /usr/local/bin/mail-queue-worker
COPY tests/differential/mailer/entrypoint.sh /usr/local/bin/differential-mailer
COPY tests/differential/mailer/seed.sql /opt/differential/seed.sql
COPY tests/differential/mailer/cert.ext /opt/differential/cert.ext
COPY tests/differential/mailer/config.toml /etc/mailer/config.toml
RUN chmod 0755 /usr/local/bin/differential-mailer
ENTRYPOINT ["/usr/local/bin/differential-mailer"]
CMD ["server"]
