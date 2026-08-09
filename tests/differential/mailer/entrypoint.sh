#!/bin/sh
set -eu

case "${1:-server}" in
  init)
    if [ ! -s /certs/ca.crt ]; then
      openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=differential-test-ca \
        -addext 'basicConstraints=critical,CA:TRUE' -keyout /tmp/ca.key -out /certs/ca.crt >/dev/null 2>&1
      openssl req -newkey rsa:2048 -nodes -subj /CN=mailer \
        -keyout /certs/server.key -out /tmp/server.csr >/dev/null 2>&1
      openssl x509 -req -in /tmp/server.csr -CA /certs/ca.crt -CAkey /tmp/ca.key \
        -CAcreateserial -days 2 -extfile /opt/differential/cert.ext \
        -out /certs/server.crt >/dev/null 2>&1
      chmod 0600 /certs/server.key
    fi
    mail-migrate up
    psql "$MAIL_DATABASE_URL" -v ON_ERROR_STOP=1 -f /opt/differential/seed.sql
    ;;
  server)
    "$0" init
    exec maild --config /etc/mailer/config.toml
    ;;
  worker) exec mail-queue-worker ;;
  *) echo "unknown mode: $1" >&2; exit 64 ;;
esac
