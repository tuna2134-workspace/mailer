# Non-root deployment hardening

`maild` must run as a dedicated unprivileged account. Binding ports below 1024 does not require a root-resident process: grant only `CAP_NET_BIND_SERVICE` through systemd `AmbientCapabilities`/`CapabilityBoundingSet`, or add only that capability to the container. An SMTP reverse proxy is not a transparent replacement for direct port 25 operation because peer address, STARTTLS, timeout, and SMTP state semantics form part of policy enforcement.

A realistic systemd service baseline is:

```ini
[Service]
User=maild
Group=maild
ExecStart=/usr/local/bin/maild --config /etc/maild/maild.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/maild
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Restart=on-failure
TimeoutStopSec=90s
```

Grant write access only to an explicitly configured transient spool if one is enabled; committed messages remain in PostgreSQL. The service still needs outbound TCP for SMTP, PostgreSQL, HTTPS/ACME and policy retrieval, UDP/TCP DNS, inbound configured listeners, and read access to manual certificate/key files. `ProtectSystem=strict` therefore must be paired with narrowly scoped `ReadWritePaths` only when a local cache or spool is configured.

Keep PostgreSQL credentials, ACME cache encryption keys, DKIM keys, and manual TLS keys outside the image and repository. Prefer systemd credentials or read-only container secrets. Container deployments should use a read-only root filesystem, drop all capabilities, then add only `NET_BIND_SERVICE`; do not use `--privileged` or run as UID 0. Validate IPv4/IPv6 reachability, DNS TCP fallback, port 443 TLS-ALPN-01 routing, certificate file permissions, and shutdown behavior before production deployment.
