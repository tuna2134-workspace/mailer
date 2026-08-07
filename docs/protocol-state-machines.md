# Protocol state machines

## SMTP

`Connected -> Greeted -> Mail -> Recipients -> Data -> Greeted`; `RSET` returns to `Greeted`, `QUIT` terminates, STARTTLS returns to a fresh post-connect SMTP state and requires a new EHLO. AUTH is allowed only on submission, after TLS, and before MAIL. Relay permission is decided for every recipient from authenticated identity plus local-domain policy; default is deny. DATA/BDAT writes to a bounded spool/DB stream and commits only after complete validation.

## IMAP

`NotAuthenticated -> Authenticated -> Selected -> Logout`. STARTTLS is only pre-auth and discards pre-TLS capability/security negotiation state. Commands are admitted by state. Literals are counted byte streams with configured limits; sequence numbers are session views, while UIDs are durable mailbox identifiers. Concurrent changes emit unsolicited responses from committed mailbox events.

## Queue

`pending -> leased -> delivered | deferred | failed | cancelled`. Lease expiry returns work to eligible state. Attempt recording and next-state transition are one transaction. A delivered recipient is never retried; partial recipient results split durable recipient states.

Every transition rejects invalid input without panic and has a transcript/state test in its implementation Phase.

