#!/usr/bin/env python3
"""Exercise a running maild with a private test CA using only Python stdlib."""

import argparse
import imaplib
import smtplib
import socket
import ssl
from email.message import EmailMessage


class VerifiedImaps(imaplib.IMAP4_SSL):
    def __init__(self, address: str, port: int, context: ssl.SSLContext):
        self._address = address
        super().__init__("mail.example.test", port, ssl_context=context)

    def _create_socket(self, timeout):
        plain = socket.create_connection((self._address, self.port), timeout)
        return self.ssl_context.wrap_socket(plain, server_hostname=self.host)


def smtp(address: str, port: int, context: ssl.SSLContext, *, authenticated: bool):
    client = smtplib.SMTP(address, port, timeout=10)
    client.ehlo()
    client._host = "mail.example.test"
    client.starttls(context=context)
    client.ehlo()
    if authenticated:
        client.login("alice@example.test", "e2e-password")
    return client


def message(sender: str, recipient: str, subject: str) -> EmailMessage:
    value = EmailMessage()
    value["From"] = sender
    value["To"] = recipient
    value["Subject"] = subject
    value.set_content(f"body for {subject}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--ca", required=True)
    parser.add_argument("--expected-subject")
    parser.add_argument("--expected-issuer", default="Mailer-E2E-Root-CA")
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)

    if args.expected_subject is None:
        with smtp(args.address, 2587, context, authenticated=True) as client:
            client.send_message(
                message("alice@example.test", "bob@example.test", "submission-e2e")
            )
        with smtp(args.address, 2525, context, authenticated=False) as client:
            client.send_message(
                message("sender@remote.test", "forward@example.test", "forward-e2e")
            )

    with VerifiedImaps(args.address, 2993, context) as client:
        assert client.login("bob@example.test", "e2e-password")[0] == "OK"
        assert client.select("INBOX")[0] == "OK"
        status, ids = client.search(None, "ALL")
        assert status == "OK" and ids[0].split()
        subjects = []
        for message_id in ids[0].split():
            status, body = client.fetch(message_id, "(BODY.PEEK[])")
            assert status == "OK"
            subjects.append(repr(body))
        joined = " ".join(subjects)
        if args.expected_subject is None:
            assert "submission-e2e" in joined and "forward-e2e" in joined
        else:
            assert args.expected_subject in joined

    with socket.create_connection((args.address, 8443), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname="mail.example.test") as tls:
            issuer = dict(item[0] for item in tls.getpeercert()["issuer"])
            assert issuer["commonName"] == args.expected_issuer

    try:
        with socket.create_connection((args.address, 8443), timeout=10) as plain:
            ssl.create_default_context().wrap_socket(
                plain, server_hostname="mail.example.test"
            )
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError("an untrusted client accepted the private CA")

    print("PASS: private CA and IMAPS", end="")
    if args.expected_subject is None:
        print(", SMTP STARTTLS, Submission, and forwarding")
    else:
        print(f", subject={args.expected_subject}")


if __name__ == "__main__":
    main()
