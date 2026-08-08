# External mailbox-provider interoperability

This is an opt-in staging procedure. It is deliberately excluded from public CI: provider availability, reputation, credentials, DNS propagation, and abuse controls are external state.

## Preconditions

- Use a dedicated staging tenant and application password. Do not use an administrator token.
- The sending IP must have stable forward and reverse DNS. PTR and forward A/AAAA must agree, and the PTR hostname must be the SMTP EHLO hostname.
- Publish MX, SPF, DKIM and DMARC records generated for the staging domain. Wait for authoritative DNS propagation before sending.
- Verify that TCP/25 outbound, TCP/587 submission, DNS, PostgreSQL and the queue worker are operational.
- Use test recipients controlled by the operator at Gmail, Outlook/Microsoft and Yahoo. Never probe third-party addresses.

Record the preflight output of `dig +dnssec MX`, `dig +dnssec TXT`, DKIM selector TXT, DMARC TXT, PTR, and forward A/AAAA lookups. A normal recursive answer without a validated secure status is not proof of DNSSEC or DANE.

## Submit probes

The script refuses plaintext submission and reads the application password from an already-open file descriptor, not argv. Example using a systemd credential or mode-0600 temporary descriptor:

```bash
exec 3</run/credentials/mail-interop-password
export MAIL_INTEROP_PASSWORD_FD=3
export MAIL_INTEROP_SUBMISSION_HOST=mail.staging.example
export MAIL_INTEROP_USERNAME=probe@staging.example
export MAIL_INTEROP_SENDER=probe@staging.example
export MAIL_INTEROP_GMAIL_TO=controlled-account@gmail.com
export MAIL_INTEROP_OUTLOOK_TO=controlled-account@outlook.com
export MAIL_INTEROP_YAHOO_TO=controlled-account@yahoo.com
python3 interoperability/external_provider_probe.py
exec 3<&-
```

Set `MAIL_INTEROP_CA_FILE` only for a staging CA that is intentionally trusted by this probe. The script has no certificate-verification bypass.

## Evidence to collect

For every printed Message-ID, save the provider's complete original-message headers and record:

- queue attempt history, destination MX, selected address, retry classification and final disposition;
- negotiated TLS version and whether transport policy was opportunistic or strict;
- provider acceptance or SMTP rejection, including enhanced status code;
- Received chain, EHLO/PTR consistency, Return-Path, Authentication-Results, SPF, DKIM and DMARC results;
- ARC chain only when a trusted intermediary actually adds ARC fields;
- DSN success/failure/delay behavior and retry behavior after a controlled temporary 4xx test.

Do not infer success from the SMTP 250 alone: placement, authentication interpretation and Received headers must be inspected. Redact addresses and provider identifiers before attaching evidence to public issues.

## Failure and retry exercises

Run temporary-failure tests only against infrastructure controlled by the operator. A staging MX can return 451 for the first attempt and accept a later retry. It can also accept DATA and close before the final response to verify that maild records delivery ambiguity rather than claiming definite failure. Do not induce these cases against Gmail, Outlook or Yahoo.
