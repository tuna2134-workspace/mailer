# Compatibility policy

Primary protocols are SMTP and IMAP4rev2. IMAP4rev1 syntax/capabilities are compatibility-only and tested against Dovecot/Cyrus and named clients. POP3, POP3S, APOP and POP STLS are never implemented. JMAP is out of scope. EHLO/CAPABILITY output is derived only from enabled, operational features.

Interoperability is tested incrementally with Postfix, Exim, OpenSMTPD, Dovecot, Cyrus, Thunderbird, Apple Mail, Outlook, iOS/Android clients, mutt/NeoMutt, Roundcube/SnappyMail, Gmail/Microsoft 365 and authentication tools. Rspamd/antivirus/OpenDKIM/OpenDMARC are external comparison/integration targets, not hidden replacements for required core parsers/state machines.

Malformed legacy input has a documented accept/reject policy and preserves raw bytes. No compatibility behavior may weaken relay, TLS/auth, tenant or resource-limit controls.

