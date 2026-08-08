# Phase 16 report

`mail-list` implements List-Id and list command headers, HTTPS-only one-click unsubscribe markers, HMAC-authenticated VERP generation/verification, bounce-recipient recovery, List-Id and hop-count loop rejection, and DMARC/ARC-aware From mitigation decisions.

Header values reject CR/LF injection. VERP authentication uses a truncated 128-bit HMAC-SHA256 tag compared in constant time. DKIM signing is delegated to the implemented `mail-dkim` boundary. Subscriber storage, HTTP unsubscribe handling, moderation, digest generation, and ARF ingestion remain a separately deployable list-management service rather than hidden protocol stubs.
