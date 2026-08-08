#!/usr/bin/env python3
"""Submit traceable staging messages without accepting secrets on argv."""

from email.message import EmailMessage
import os
import smtplib
import ssl
import sys
import uuid


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"{name} is required")
    return value


def password_from_fd() -> str:
    raw_fd = required("MAIL_INTEROP_PASSWORD_FD")
    fd = int(raw_fd)
    secret = os.read(fd, 16 * 1024).rstrip(b"\r\n")
    if not secret:
        raise ValueError("password file descriptor was empty")
    return secret.decode("utf-8")


def recipients() -> list[tuple[str, str]]:
    return [
        ("gmail", required("MAIL_INTEROP_GMAIL_TO")),
        ("outlook", required("MAIL_INTEROP_OUTLOOK_TO")),
        ("yahoo", required("MAIL_INTEROP_YAHOO_TO")),
    ]


def message(sender: str, provider: str, recipient: str) -> EmailMessage:
    probe_id = uuid.uuid4()
    value = EmailMessage()
    value["From"] = sender
    value["To"] = recipient
    value["Subject"] = f"mailer interoperability probe {provider} {probe_id}"
    value["Message-ID"] = f"<{probe_id}@{sender.rsplit('@', 1)[-1]}>"
    value["Auto-Submitted"] = "auto-generated"
    value.set_content(
        "Staging interoperability probe. Record the provider's full received headers.\n"
    )
    return value


def main() -> int:
    host = required("MAIL_INTEROP_SUBMISSION_HOST")
    port = int(os.environ.get("MAIL_INTEROP_SUBMISSION_PORT", "587"))
    username = required("MAIL_INTEROP_USERNAME")
    sender = required("MAIL_INTEROP_SENDER")
    password = password_from_fd()
    context = ssl.create_default_context(cafile=os.environ.get("MAIL_INTEROP_CA_FILE"))
    with smtplib.SMTP(host, port, timeout=30) as client:
        client.ehlo()
        if not client.has_extn("starttls"):
            raise RuntimeError("submission endpoint did not advertise STARTTLS")
        client.starttls(context=context)
        client.ehlo()
        client.login(username, password)
        for provider, recipient in recipients():
            value = message(sender, provider, recipient)
            mail_options = ["SMTPUTF8"] if client.has_extn("smtputf8") else []
            rcpt_options = ["NOTIFY=SUCCESS,FAILURE,DELAY"] if client.has_extn("dsn") else []
            client.send_message(
                value,
                from_addr=sender,
                to_addrs=[recipient],
                mail_options=mail_options,
                rcpt_options=rcpt_options,
            )
            print(f"{provider}: {value['Message-ID']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, smtplib.SMTPException) as error:
        print(f"probe failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
