FROM debian:12.11-slim
ARG DOVECOT_VERSION=1:2.3.19.1+dfsg1-2.1+deb12u6
RUN apt-get update \
 && apt-get install -y --no-install-recommends "dovecot-core=${DOVECOT_VERSION}" "dovecot-imapd=${DOVECOT_VERSION}" netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail \
 && useradd -u 5000 -g vmail -d /mail vmail
COPY tests/differential/dovecot/dovecot.conf /etc/dovecot/dovecot.conf
COPY tests/differential/dovecot/users /etc/dovecot/users
COPY tests/differential/dovecot/entrypoint.sh /usr/local/bin/differential-dovecot
RUN chmod 0644 /etc/dovecot/users && chmod 0755 /usr/local/bin/differential-dovecot
ENTRYPOINT ["/usr/local/bin/differential-dovecot"]
