FROM debian:12.11-slim
ARG POSTFIX_VERSION=3.7.11-0+deb12u1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && echo 'postfix postfix/main_mailer_type select No configuration' | debconf-set-selections \
 && apt-get install -y --no-install-recommends "postfix=${POSTFIX_VERSION}" netcat-openbsd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY tests/differential/postfix/main.cf /etc/postfix/main.cf
COPY tests/differential/postfix/entrypoint.sh /usr/local/bin/differential-postfix
RUN chmod 0755 /usr/local/bin/differential-postfix
ENTRYPOINT ["/usr/local/bin/differential-postfix"]
