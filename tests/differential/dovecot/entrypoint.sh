#!/bin/sh
set -eu
mkdir -p /mail/alice@example.test/Maildir/cur /mail/alice@example.test/Maildir/new /mail/alice@example.test/Maildir/tmp
chown -R vmail:vmail /mail
dovecot -n
exec dovecot -F
