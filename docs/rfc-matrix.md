# RFC implementation matrix (initial)

Snapshot: 2026-08-07. Primary metadata source: [RFC Editor XML index](https://www.rfc-editor.org/rfc-index.xml); registries: [SMTP](https://www.iana.org/assignments/smtp/), [IMAP capabilities](https://www.iana.org/assignments/imap-capabilities/), [message headers](https://www.iana.org/assignments/message-headers/). Errata are checked per RFC before implementation. `—` means the index has no relationship; `unverified` means deliberately not claimed. A row is never `implemented` until its conformance test exists.

Policy abbreviations: `F/P/E/N` = full/partial/external/not planned. Priority: `C/R/M/O/L/X/E/OOS` = core/required/recommended/optional/legacy/experimental/external/out of scope. Status uses RFC Editor's current status. Phase and crate identify planned ownership; tests are planned names prefixed `planned:`.

| RFC | Formal title | Status | Area | Currency | Obsoletes | Obsoleted by | Updates | Updated by | Policy | Priority | Phase | Crate | Conformance test | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5321 | Simple Mail Transfer Protocol | Draft Standard | SMTP | current | 2821 | — | 1123 | 7504 | partial | core | 4,5 | mail-smtp-proto,mail-smtp-server,mail-smtp-client,mail-delivery | parser_and_state_transcript;local_delivery_transcript_and_relay_denial;streaming_ingestion_and_atomic_local_delivery;dot_stuffing_survives_chunk_boundaries;queue_lease_stream_result_and_bounce_are_atomic | Phase 5 adds Sections 4.1.1, 4.2, 4.4, 4.5.4.1 and 5 routing/retry subset; outbound STARTTLS and full DSN remain later phases |
| 7504 | SMTP 521 and 556 Reply Codes | Proposed Standard | SMTP | current | — | — | 1846,5321 | — | F | R | 4 | mail-smtp-proto | planned:smtp_7504 | null-service replies |
| 6409 | Message Submission for Mail | Internet Standard | Submission | current | 4409 | — | — | 8314 | F | C | 4,7 | mail-submission | planned:submission_6409 | authenticated submission |
| 2033 | Local Mail Transfer Protocol | Informational | LMTP | current | — | — | — | — | P | O | 5 | mail-lmtp | planned:lmtp_2033 | optional local integration |
| 1870 | SMTP Service Extension for Message Size Declaration | Internet Standard | SIZE | current | 1653 | — | — | — | F | R | 7 | mail-smtp-proto | planned:size_1870 | advertise configured limit only |
| 2920 | SMTP Service Extension for Command Pipelining | Internet Standard | PIPELINING | current | 2197 | — | — | — | F | R | 7 | mail-smtp-proto | planned:pipelining_2920 | bounded command queue |
| 6152 | SMTP Service Extension for 8-bit MIME Transport | Internet Standard | 8BITMIME | current | 1652 | — | — | — | F | R | 7 | mail-smtp-proto | planned:8bitmime_6152 | no silent downgrade |
| 3030 | SMTP Service Extensions for Transmission of Large and Binary MIME Messages | Proposed Standard | CHUNKING/BINARYMIME | current | 1830 | — | — | — | F | O | 7 | mail-smtp-proto | planned:bdat_3030 | streaming BDAT |
| 3207 | SMTP Service Extension for Secure SMTP over TLS | Proposed Standard | STARTTLS | current | 2487 | — | — | 7817 | F | R | 7 | mail-smtp-server | planned:starttls_3207 | reset post-TLS state |
| 4954 | SMTP Service Extension for Authentication | Proposed Standard | AUTH | current | 2554 | — | 3463 | 5248 | F | R | 7 | mail-sasl,mail-submission | planned:auth_4954 | AUTH unavailable without TLS |
| 8689 | SMTP Require TLS Option | Proposed Standard | REQUIRETLS | current | — | — | — | — | F | R | 7,15 | mail-policy | planned:requiretls_8689 | end-to-end policy |
| 2852 | Deliver By SMTP Service Extension | Proposed Standard | DELIVERBY | current | — | — | 1894 | — | F | O | 7 | mail-delivery | planned:deliverby_2852 | bounded deadlines |
| 4865 | SMTP Submission Service Extension for Future Message Release | Proposed Standard | FUTURERELEASE | current | — | — | 3463,3464 | — | F | O | 7 | mail-submission | planned:futurerelease_4865 | tenant limits |
| 3461 | SMTP Extension for Delivery Status Notifications | Draft Standard | DSN | current | 1891 | — | — | 3798,3885,5337,6533,8098 | F | R | 5,13 | mail-dsn | planned:dsn_3461 | NOTIFY/ORCPT/RET/ENVID |
| 3463 | Enhanced Mail System Status Codes | Draft Standard | SMTP status | current | 1893 | — | — | 3886,4468,4865,4954,5248 | partial | core | 4 | mail-smtp-proto | parser_and_state_transcript | Core success, syntax, address, size, sequence and temporary-system codes implemented; registry expansion remains |
| 3464 | An Extensible Message Format for Delivery Status Notifications | Draft Standard | DSN | current | 1894 | — | — | 4865,5337,6533 | F | R | 13 | mail-dsn | planned:dsn_format_3464 | multipart/report |
| 5248 | A Registry for SMTP Enhanced Mail System Status Codes | BCP | SMTP status | current | — | — | 3463,4468,4954 | — | F | R | 4 | mail-core | planned:status_registry | sync with IANA |
| 5322 | Internet Message Format | Draft Standard | IMF | current | 2822 | — | 4021 | 6854 | F | C | 6 | mail-message,address | planned:imf_5322 | trace fields and arbitrary octets |
| 6854 | Update to IMF to Allow Group Syntax in From/Sender | Proposed Standard | IMF | current | — | — | 5322 | — | F | R | 6 | mail-message | planned:imf_6854 | group syntax |
| 2045 | MIME Part One: Format of Internet Message Bodies | Draft Standard | MIME/CTE | current | 1521,1522,1590 | — | — | 2184,2231,5335,6532 | F | C | 6 | mail-mime | planned:mime_2045 | bounded streaming |
| 2046 | MIME Part Two: Media Types | Draft Standard | MIME | current | 1521,1522,1590 | — | — | 2646,3798,5147,6657,8098 | F | C | 6 | mail-mime | planned:mime_2046 | multipart depth/part limits |
| 2047 | MIME Part Three: Message Header Extensions for Non-ASCII Text | Draft Standard | MIME | current | 1521,1522,1590 | — | — | 2184,2231 | F | R | 6 | mail-message | planned:mime_2047 | encoded words |
| 2049 | MIME Part Five: Conformance Criteria and Examples | Draft Standard | MIME | current | 1521,1522,1590 | — | — | — | F | R | 6 | mail-mime | planned:mime_2049 | conformance cases |
| 2183 | Content-Disposition Header Field | Proposed Standard | MIME | current | 1806 | — | — | 2184,2231 | F | R | 6 | mail-mime | planned:disposition_2183 | filename is untrusted data |
| 2231 | MIME Parameter Value and Encoded Word Extensions | Proposed Standard | MIME | current | 2184 | — | 2045,2047,2183 | — | F | R | 6 | mail-mime | planned:mime_params_2231 | continuation limits |
| 6838 | Media Type Specifications and Registration Procedures | BCP | Media types | current | 4288 | — | — | 9694 | P | R | 6 | mail-mime | planned:media_type_6838 | registry integration |
| 6530 | Overview and Framework for Internationalized Email | Proposed Standard | EAI | current | 4952,5504,5825 | — | — | — | F | R | 7 | mail-address | planned:eai_6530 | framework |
| 6531 | SMTP Extension for Internationalized Email | Proposed Standard | SMTPUTF8 | current | 5336 | — | — | — | F | R | 7 | mail-smtp-proto | planned:smtputf8_6531 | no false advertisement |
| 6532 | Internationalized Email Headers | Proposed Standard | EAI/IMF | current | 5335 | — | 2045 | — | F | R | 6,7 | mail-message | planned:eai_headers_6532 | UTF-8 validation |
| 6533 | Internationalized Delivery Status and Disposition Notifications | Proposed Standard | EAI/DSN | current | 5337 | — | 3461,3464,3798,6522 | — | F | M | 13 | mail-dsn | planned:eai_dsn_6533 | UTF-8 DSN |
| 5890-5894 | IDNA Definitions, Protocol, Tables, Bidi, Rationale | Proposed/Informational | IDNA | current | 3490/3491 (where stated) | — | see RFC index | 5892 updated by 8753 | P | R | 6 | mail-address,dns | planned:idna_589x | use IDNA library; mapping policy documented |
| 5198 | Unicode Format for Network Interchange | Proposed Standard | Unicode | current | 698 | — | 854 | — | P | R | 6 | mail-address | planned:unicode_5198 | normalization boundaries |
| 4422 | Simple Authentication and Security Layer (SASL) | Proposed Standard | SASL | current | 2222 | — | — | — | F | C | 7,9 | mail-sasl | planned:sasl_4422 | authzid/authcid separation |
| 4616 | PLAIN SASL Mechanism | Proposed Standard | SASL | current | — | — | 2595 | 8996 | F | R | 7,9 | mail-sasl | planned:plain_4616 | TLS only |
| 5802 | SCRAM SASL and GSS-API Mechanisms | Proposed Standard | SASL | current | — | — | — | 7677,9266 | P | R | 7,9 | mail-sasl | planned:scram_5802 | SHA-1 mechanism not advertised |
| 7677 | SCRAM-SHA-256 and -PLUS | Proposed Standard | SASL | current | — | — | 5802 | 9266 | F | R | 7,9 | mail-sasl | planned:scram_7677 | PLUS requires binding |
| 5929/9266 | Channel Bindings for TLS / TLS 1.3 | Proposed Standard | SASL/TLS | current | — | — | 9266 updates 5929 and SCRAM RFCs | — | F | R | 7,9 | mail-sasl,tls | planned:binding_9266 | exporter details verified at implementation |
| 8314 | Cleartext Considered Obsolete: TLS for Email Submission and Access | Proposed Standard | TLS | current | — | — | 1939,2595,3501,5068,6186,6409 | 8997 | F | R | 3,7,9 | mail-tls | planned:tls_8314 | POP clauses are not implemented |
| 7817 | TLS Server Identity Check for Email Protocols | Proposed Standard | TLS | current | — | — | 2595,3207,3501,5804 | — | F | R | 3 | mail-tls | planned:identity_7817 | client verification |
| 8996 | Deprecating TLS 1.0 and TLS 1.1 | BCP | TLS | current | 5469,7507 | — | many, incl. 3501/4616 | — | F | R | 3 | mail-tls | planned:tls_versions_8996 | modern rustls policy |
| 8555 | Automatic Certificate Management Environment (ACME) | Proposed Standard | ACME | current | — | — | — | — | external | external | 3 | mail-acme | encrypted_cache_and_distributed_lock | Protocol engine supplied by pinned tokio-rustls-acme 0.9.1; cache, lifecycle and locking integrated locally |
| 8737 | ACME TLS-ALPN Challenge Extension | Proposed Standard | ACME | current | — | — | — | — | external | external | 3 | mail-acme | maild listener integration | tokio-rustls-acme AcmeAcceptor; CA must reach TCP/443 |
| 1034/1035 | Domain Names Concepts / Implementation | Internet Standard | DNS/MX | current | 882,883,973 | — | — | many; see index | P | C | 5 | mail-dns | route_types_do_not_confuse_null_mx_with_an_empty_host_list | System resolver integration; MX ordering and A/AAAA address lookup implemented; DNSSEC state remains Phase 15 |
| 7505 | A Null MX No Service Resource Record | Proposed Standard | DNS/MX | current | — | — | — | — | full | required | 5 | mail-dns | route_types_do_not_confuse_null_mx_with_an_empty_host_list | Single preference-0 root exchange suppresses implicit MX fallback; mixed root MX is rejected |
| 4033-4035 | DNSSEC Introduction, RRs, Protocol Modifications | Proposed Standard | DNSSEC | current | earlier DNSSEC suite | — | core DNS RFCs | later clarifications | E | E | 15 | mail-dns | planned:dnssec_state | resolver-provided validation state |
| 7208 | Sender Policy Framework (SPF) | Proposed Standard | SPF/Received-SPF | current | 4408 | — | — | 7372,8553,8616 | F | R | 12 | mail-spf | planned:spf_7208 | lookup/void/recursion budgets |
| 6376 | DomainKeys Identified Mail Signatures | Internet Standard | DKIM | current | 4871,5672 | — | — | 8301,8463,8553,8616 | F | R | 12 | mail-dkim | planned:dkim_6376 | raw-byte canonicalization |
| 8301 | DKIM Algorithm and Key Usage Update | Proposed Standard | DKIM | current | — | — | 6376 | — | F | R | 12 | mail-dkim | planned:dkim_crypto_8301 | key floor |
| 8463 | New DKIM Cryptographic Signature Method | Proposed Standard | DKIM | current | — | — | 6376 | — | F | R | 12 | mail-dkim | planned:dkim_ed25519_8463 | Ed25519 |
| 9989 | Domain-Based Message Authentication, Reporting, and Conformance (DMARC) | Proposed Standard | DMARC | current | 7489,9091 | — | — | — | F | R | 12 | mail-dmarc | planned:dmarc_9989 | current protocol core |
| 9990 | DMARC Aggregate Reporting | Proposed Standard | DMARC reports | current | 7489 | — | — | — | F | M | 12 | mail-dmarc | planned:dmarc_agg_9990 | report abuse controls |
| 9991 | DMARC Failure Reporting | Proposed Standard | DMARC reports | current | 7489 | — | 6591 | — | P | O | 12 | mail-dmarc | planned:dmarc_failure_9991 | privacy gated |
| 7489 | DMARC | Informational | DMARC | obsolete | — | 9989,9990,9991 | — | 8553,8616 | N | L | — | none | none | retained for compatibility history |
| 8601 | Message Header Field for Indicating Message Authentication Status | Proposed Standard | Authentication-Results | current | 7601 | — | — | — | F | R | 12 | mail-policy | planned:auth_results_8601 | trusted-hop boundary |
| 8617 | Authenticated Received Chain (ARC) Protocol | Experimental | ARC | current experimental | — | — | — | — | F | X | 12 | mail-arc | planned:arc_8617 | never label standards-track |
| 7672 | SMTP Security via Opportunistic DANE TLS | Proposed Standard | DANE | current | — | — | — | — | E/P | E | 15 | mail-dns,delivery | planned:dane_7672 | requires validated DNSSEC |
| 8461 | SMTP MTA Strict Transport Security | Proposed Standard | MTA-STS | current | — | — | — | — | F | R | 15 | mail-policy | planned:mta_sts_8461 | HTTPS policy cache |
| 8460 | SMTP TLS Reporting | Proposed Standard | TLS-RPT | current | — | — | — | — | F | R | 15 | mail-policy | planned:tls_rpt_8460 | aggregation/privacy limits |
| 9051 | IMAP Version 4rev2 | Proposed Standard | IMAP | current | 3501 | — | — | — | F | C | 9-11 | mail-imap-proto/server | planned:imap_9051 | primary mailbox-access protocol |
| 3501 | IMAP Version 4rev1 | Proposed Standard | IMAP | obsolete | 2060 | 9051 | — | many | P | L | 9-11 | mail-imap-proto | planned:imap_rev1_compat | compatibility only |
| 9755 | IMAP Support for UTF-8 | Proposed Standard | IMAP | current | 6855 | — | — | — | F | R | 9-10 | mail-imap-proto | planned:imap_utf8_9755 | replaces 6855 |
| 2177/4315/6851 | IDLE / UIDPLUS / MOVE | Proposed Standard | IMAP | current | UIDPLUS obsoletes 2359 | — | — | — | F | R | 10-11 | mail-imap-server | planned:imap_core_ext | concurrency-sensitive |
| 7162 | CONDSTORE and QRESYNC | Proposed Standard | IMAP sync | current | 4551,5162 | — | 2683 | — | F | R | 11 | mail-imap-server,mailbox | planned:qresync_7162 | monotonic MODSEQ |
| 4731/5182/5256/5267/5032/9394 | ESEARCH, SEARCHRES, SORT/THREAD, CONTEXT, WITHIN, PARTIAL | Proposed Standard | IMAP search | current | — | — | see index | 4731/5267 updated by 9394 | F | O | 10,15 | mail-search | planned:imap_search_ext | staged after core search |
| 5258/5819/6154 | LIST-EXTENDED, LIST-STATUS, SPECIAL-USE | Proposed Standard | IMAP list | current | — | — | — | — | F | O | 10 | mail-imap-server | planned:imap_list_ext | registry-driven |
| 5464/8474/8514/8970/9208 | METADATA, OBJECTID, SAVEDATE, PREVIEW, QUOTA | Proposed Standard | IMAP extensions | current | QUOTA obsoletes 2087 | — | OBJECTID updates 3501 | — | F | O | 10,15 | mail-imap-server | planned:imap_optional_ext | per-extension tests |
| 7888 | IMAP4 Non-synchronizing Literals | Proposed Standard | IMAP literal | current | 2088 | — | — | — | F | R | 9 | mail-imap-proto | planned:literal_7888 | bounded streaming |
| 4959 | IMAP SASL Initial Client Response | Proposed Standard | IMAP AUTH | current | — | — | — | — | F | R | 9 | mail-imap-server | planned:sasl_ir_4959 | capability gated |
| 5804 | Protocol for Remotely Managing Sieve Scripts | Proposed Standard | ManageSieve | current | — | — | — | 7817,8553 | P | O | 14 | mail-sieve | planned:managesieve_5804 | after execution engine |
| 5228 | Sieve: An Email Filtering Language | Proposed Standard | Sieve | current | 3028 | — | — | 5229,5429,6785,9042 | F | R | 14 | mail-sieve | planned:sieve_5228 | instruction/time/memory limits |
| 5173/5183/5229/5230/5231/5235/5429/5435/5463/5293/6609/7352 | Sieve Body, Environment, Variables, Vacation, Relational, Spam/Virus, Reject, Notify, Ihave, Editheader, Include, Duplicate | Proposed Standard | Sieve extensions | current | some replace earlier RFCs | — | see index | Vacation/Notify later updated | F/P | M/O | 14 | mail-sieve | planned:sieve_extensions | external scanners for spam/virus |
| 8098 | Message Disposition Notification | Internet Standard | MDN | current | 3798 | — | 2046,3461 | — | F | M | 13 | mail-dsn | planned:mdn_8098 | consent and deduplication |
| 3834 | Recommendations for Automatic Responses to Electronic Mail | Proposed Standard | Auto-response | current | — | — | — | 5436 | F | R | 13,14 | mail-policy | planned:auto_reply_3834 | loop/backscatter protection |
| 2369/2919/8058 | List command headers / List-ID / One-click | Proposed Standard | Mailing lists | current | — | — | — | — | F | M | 16 | external list service | planned:list_headers | separated service |
| 5965 | Extensible Format for Email Feedback Reports | Proposed Standard | ARF | current | — | — | — | 6650 | P | O | 16 | mail-message | planned:arf_5965 | ingestion limits |
| 5652/8551/9788 | CMS / S/MIME 4.0 / Header Protection | Internet/Proposed Standard | S/MIME | current | earlier CMS/S-MIME | — | — | later updates | P | O | 17 | mail-message | planned:smime_structure | crypto/key UI external |
| 3156 | MIME Security with OpenPGP | Proposed Standard | OpenPGP/MIME | current | — | — | 2015 | — | P | O | 17 | mail-mime | planned:pgp_mime_structure | crypto/key management external |
| 6068/2392 | mailto URI / Content-ID and Message-ID URLs | Proposed Standard | URI | current | 2368/2111 | — | — | — | F | M | 6,16 | mail-message | planned:mail_uris | safe URI parsing |
| 3864 | Registration Procedures for Message Header Fields | BCP | Header registry | current | — | — | — | 9110 | E | E | 6 | mail-message | planned:header_registry | IANA registry is authoritative |
| 8620/8621 | JMAP / JMAP for Mail | Proposed Standard | JMAP | current | — | — | 8621 updates 5788 | later updates | N | OOS | — | none | none | IMAP-only mailbox access scope |
| 9457 | Problem Details for HTTP APIs | Proposed Standard | HTTP API | current | 7807 | — | — | — | F | R | 2 | mail-admin-api | planned:problem_9457 | extension members `code`,`request_id` |
| — | OpenAPI Specification 3.1.x | external specification | API schema | current version unverified until implementation | — | — | — | — | E | E | 2 | mail-admin-api | planned:openapi_validation | not an RFC; pin version in Phase 2 |
| 1939 and POP-related RFCs | Post Office Protocol - Version 3 and extensions | mixed | POP3 | legacy/out of scope | unverified | unverified | unverified | unverified | N | OOS | — | none | none | mailbox access is unified on IMAP; no POP3/POP3S/APOP/STLS |

## Classification summary

1. Core: SMTP/Submission, IMF/MIME/address parsing, PostgreSQL storage/queue, mailbox invariants, IMAP4rev2.
2. Required for modern interoperability: TLS, SMTPUTF8, AUTH/SASL, DSN/status, SPF/DKIM/DMARC, common IMAP extensions.
3. Recommended: ARC, MTA-STS/TLS-RPT, Sieve, MDN, list headers.
4. Optional: LMTP, advanced IMAP search/metadata, ManageSieve, S/MIME/OpenPGP structure.
5. Legacy: IMAP4rev1 compatibility and obsolete RFC parsing only.
6. Experimental: ARC is explicitly tracked as Experimental.
7. External integration: ACME library, DNS/DNSSEC resolver, PSL, OAuth/OIDC, scanners, secret manager.
8. Out of scope: POP3 and JMAP mailbox access.

## Verification rule

Before each implementation PR: open the RFC Editor info page and errata page, compare IANA registry values, extract normative requirements into `docs/conformance/rfcNNNN.md`, and map every implemented MUST/MUST NOT to a runnable test. Unknown extension semantics remain `unverified`.
