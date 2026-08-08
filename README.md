# mailer

Rust/Tokio、PostgreSQL、rustlsで構築されたインターネットメールサーバです。SMTP受信・送信、Submission、IMAP、配送queue、管理API、ACME TLS-ALPN-01を同一workspaceで提供します。POP3は実装しません。

> 現在の実行設定は環境変数方式です。設計文書にあるTOML loaderや外部secret manager adapterは、現行の`maild`実行バイナリにはまだ接続されていません。

## 必要なもの

- Rust 1.88以降
- PostgreSQL（`pgcrypto`を利用可能なもの）
- 公開メールサーバとして動かす場合は、TCP 25、443、465、587、143、993の到達性
- ACME対象ホスト名を指すDNS A/AAAAレコード
- TCP/443を`maild`へ転送できるネットワーク構成

TCP/443はTLS-ALPN-01専用です。SMTP 465やIMAPS 993では証明書を取得できません。最初は必ずACME stagingを使用してください。

## ビルド

```console
cargo build --workspace --release
```

主なバイナリは次のとおりです。

| バイナリ | 用途 |
| --- | --- |
| `maild` | SMTP、Submission、IMAP、ACME、HTTPS管理API |
| `mail-queue-worker` | PostgreSQL配送queueの外部配送 |
| `mail-migrate` | SQLx migrationの適用・確認 |
| `mailctl` | HTTPS管理API client |

## PostgreSQLの準備

データベースと専用roleを作成し、接続URLをsecret-capableな環境から渡します。

```console
export MAIL_DATABASE_URL='postgresql://maild@127.0.0.1/maild'
cargo run --release -p mail-migrate -- up
cargo run --release -p mail-migrate -- check
```

`maild`はmigrationを自動適用しません。schemaが一致しない場合はlistenerを開始せず終了します。本番migrationの前にはバックアップを取得してください。詳細は[PostgreSQL運用](docs/postgresql-operations.md)と[バックアップ／復旧](docs/postgresql-backup-restore.md)を参照してください。

## 初回管理API token

通常のtoken作成・失効は`mailctl token`を使います。ただし、最初のsystem administrator tokenだけは認証済みAPI clientがまだ存在しないため、管理されたPostgreSQLセッションで一度だけ登録します。

1. 暗号学的にランダムな十分長いtokenをsecret manager等で生成します。
2. tokenのSHA-256を16進文字列として計算します。
3. 次のSQLの`TOKEN_SHA256_HEX`をhashへ置き換えて実行します。平文tokenはSQL、shell履歴、ログへ書かないでください。

```sql
INSERT INTO api_tokens (
    id, tenant_id, display_name, token_hash, scopes
) VALUES (
    gen_random_uuid(),
    NULL,
    'bootstrap-system-administrator',
    decode('TOKEN_SHA256_HEX', 'hex'),
    ARRAY[
        'tenants:read', 'tenants:write',
        'domains:read', 'domains:write',
        'users:read', 'users:write',
        'aliases:read', 'aliases:write',
        'mailboxes:read', 'mailboxes:write',
        'queue:read', 'queue:retry', 'queue:delete',
        'certificates:read', 'certificates:renew',
        'audit:read', 'metrics:read'
    ]
);
```

登録後、平文tokenはsecret managerへ保存します。後続tokenをAPIで作成したらbootstrap tokenを失効させることを推奨します。

## `maild`の設定と起動

必須環境変数:

| 変数 | 内容 |
| --- | --- |
| `MAIL_DATABASE_URL` | PostgreSQL接続URL |
| `MAIL_ACME_DOMAINS` | ACME利用時の証明書対象名のカンマ区切り一覧 |
| `MAIL_ACME_CONTACTS` | ACME利用時の`mailto:`形式の連絡先一覧 |
| `MAIL_ACME_CACHE_KEY_HEX` | ACME利用時のprivate material暗号化用32 byte keyの64桁hex |

主な任意環境変数:

| 変数 | default |
| --- | --- |
| `MAIL_HOSTNAME` | 最初のACME domain |
| `MAIL_ACME_PRODUCTION` | `false`相当。`true`でproduction |
| `MAIL_ACME_LISTEN` | `0.0.0.0:443` |
| `MAIL_ADMIN_LISTEN` | `127.0.0.1:8443` |
| `MAIL_SMTP_LISTEN` | `0.0.0.0:25` |
| `MAIL_SUBMISSION_LISTEN` | `0.0.0.0:587` |
| `MAIL_SUBMISSIONS_LISTEN` | `0.0.0.0:465` |
| `MAIL_IMAP_LISTEN` | `0.0.0.0:143` |
| `MAIL_IMAPS_LISTEN` | `0.0.0.0:993` |
| `MAIL_TLS_CERT_FILE` | 手動証明書chainのPEMファイル |
| `MAIL_TLS_KEY_FILE` | 手動証明書private keyのPEMファイル |

stagingでの起動例:

```console
export MAIL_DATABASE_URL='postgresql://maild@127.0.0.1/maild'
export MAIL_ACME_DOMAINS='mail.example.com,smtp.example.com,imap.example.com,api.mail.example.com'
export MAIL_ACME_CONTACTS='mailto:postmaster@example.com'
export MAIL_ACME_CACHE_KEY_HEX='64桁のランダムなhex文字列'
export MAIL_HOSTNAME='mail.example.com'
cargo run --release -p maild
```

ACME staging取得、SNI、SMTP STARTTLS、Submission、IMAPS、管理APIを確認してから、`MAIL_ACME_PRODUCTION=true`へ切り替えてください。ACME cache encryption keyを失うと、PostgreSQL内の証明書private materialを復号できません。DBバックアップとは別に保管してください。

手動証明書を使う場合は`MAIL_HOSTNAME`、`MAIL_TLS_CERT_FILE`、`MAIL_TLS_KEY_FILE`を設定します。この場合ACME用変数とTCP/443 listenerは不要です。証明書ファイルにはleafから中間CAまでのchainを含め、private keyはmaild実行ユーザーだけが読める権限にしてください。二つのファイル変数の片方だけを設定すると起動を拒否します。

## 配送worker

外部宛メールを配送するには、`maild`とは別にworkerを起動します。

```console
export MAIL_DATABASE_URL='postgresql://maild@127.0.0.1/maild'
export MAIL_HOSTNAME='mail.example.com'
cargo run --release -p mail-queue-worker
```

複数workerを起動できます。queue itemはPostgreSQL leaseと`FOR UPDATE SKIP LOCKED`で排他され、期限切れleaseは回収されます。

## `mailctl`

`mailctl`はDBへ直接接続せず、管理APIを使用します。

```console
export MAIL_API_URL='https://api.mail.example.com:8443'
export MAIL_API_TOKEN='secret managerから取得したtoken'
cargo run --release -p mailctl -- tenant list
```

自己署名証明書を無条件に許可するoptionはありません。API hostnameをACME domainへ含め、証明書と正しく一致させてください。管理APIはdefaultでloopback bindなので、管理端末からは安全なtunnelまたは管理networkを使用し、必要なら管理hostnameをローカルDNSでloopback／管理IPへ解決します。localhostで平文HTTPを使う構成はclient library上可能ですが、`maild`の管理APIはTLSで起動します。

作成・更新payloadは標準入力からJSONで渡します。passwordやtokenをcommand-line引数へ置かないでください。

テナント作成:

```console
printf '%s' '{"name":"Example"}' |
  cargo run --release -p mailctl -- tenant create
```

domain作成:

```console
printf '%s' '{"tenant_id":"TENANT_UUID","name":"example.com"}' |
  cargo run --release -p mailctl -- domain create
```

user作成:

```console
printf '%s' '{
  "tenant_id":"TENANT_UUID",
  "domain_id":"DOMAIN_UUID",
  "local_part":"alice",
  "display_name":"Alice",
  "password":"十分に長い初期パスワード",
  "quota_bytes":10737418240,
  "enabled":true
}' | cargo run --release -p mailctl -- user create
```

alias作成:

```console
printf '%s' '{
  "tenant_id":"TENANT_UUID",
  "source":"sales@example.com",
  "kind":"forwarding",
  "targets":["alice@example.com"]
}' | cargo run --release -p mailctl -- alias create
```

scoped token作成ではsecretが一度だけ返されます。

```console
printf '%s' '{
  "tenant_id":"TENANT_UUID",
  "display_name":"automation",
  "scopes":["users:read","domains:read"],
  "expires_at":null,
  "allowed_source_networks":["192.0.2.0/24"]
}' | cargo run --release -p mailctl -- token create
```

利用可能なcommandと引数は実行中のbinaryを正として確認できます。

```console
cargo run -p mailctl -- --help
cargo run -p mailctl -- user --help
```

`mailctl config check`、`database check`、`migration status`、`rfc status`、`conformance report`は現在placeholder responseを返し、運用checkを実行しません。migration確認には`mail-migrate check`を使用してください。

## メールclient設定

| 用途 | port | TLS | 認証 |
| --- | ---: | --- | --- |
| SMTP受信（MTA間） | 25 | STARTTLS | 通常はなし。中継不可 |
| Message Submission | 587 | STARTTLS必須 | PLAINまたはSCRAM-SHA-256 |
| implicit TLS Submission | 465 | implicit TLS | PLAINまたはSCRAM-SHA-256 |
| IMAP | 143 | STARTTLS後のみ認証 | server capabilityに従う |
| IMAPS | 993 | implicit TLS | server capabilityに従う |

送信usernameは作成したメールアドレス、passwordはuser passwordまたはapplication passwordです。認証前relayは拒否されます。

## DNS

最低限、次を公開します。

- MX: 受信SMTP hostname
- A/AAAA: 公開するSMTP、IMAP、API hostname
- PTR: outbound source IPに対応するhostname
- SPF、DKIM、DMARC
- 必要に応じてMTA-STSとTLS-RPT

TCP/25で受信したメッセージは、保存確定前にSPF、DKIM、DMARC、ARCを評価し、信頼境界側で生成した`Authentication-Results`と`Received-SPF`を付与します。DKIM/ARCの本文ハッシュはPostgreSQLの受信chunkからストリーミング計算されます。DMARC discoveryとrelaxed alignmentはMozilla Public Suffix Listに基づく組織ドメインfallbackを使用します。ARCは最新AMSと全ARC-SealをDNS公開鍵で検証し、構造検査だけでは`arc=pass`にしません。DKIMを設定したqueue workerは、受信認証結果を持つ中継メッセージへ同じ管理鍵で新しいAAR、AMS、ARC-Sealを追加します。

outbound DKIM署名を有効にする場合は、queue workerへ次をすべて設定します。秘密鍵fileはPKCS#8 DER形式で、未設定時は意図的に署名しません。不完全な設定や署名失敗時はメールを未署名で送らず、一時失敗としてqueueへ戻します。

```console
export MAIL_DKIM_DOMAIN='example.com'
export MAIL_DKIM_SELECTOR='mail2026'
export MAIL_DKIM_KEY_FILE='/run/credentials/mail-dkim.pk8'
export MAIL_DKIM_ALGORITHM='ed25519-sha256' # または rsa-sha256
cargo run --release -p mail-queue-worker
```

秘密鍵はrepositoryや環境変数へ直接格納せず、systemd credential、Kubernetes Secret等からread-only fileとしてmountしてください。対応する`${MAIL_DKIM_SELECTOR}._domainkey.${MAIL_DKIM_DOMAIN}` TXT recordの公開は別途必要です。

DNSSEC、DANE、MTA-STS、TLS-RPTはpolicy coreと外部resolver/providerの境界を持ちます。外部検証器を接続していない状態を「検証済み」とは扱いません。

## 停止

`maild`とqueue workerはCtrl-Cを処理します。Unix上の`maild`はSIGTERMも処理します。process managerでは十分な停止猶予を設定してください。

## テスト

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

PostgreSQL integration testは`MAIL_TEST_DATABASE_URL`へ実際のPostgreSQLを指定します。SQLiteは代替として使用しません。

```console
export MAIL_TEST_DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:55432/mailer'
cargo test -p mail-postgres --tests
```

## セキュリティ上の注意

- 管理APIをpublic networkへ直接bindしないでください。
- ACME cache key、API token、password、DKIM/private keyをログやshell履歴へ残さないでください。
- production ACMEへ切り替える前にstagingで検証してください。
- TCP/25のoutbound通信制限とreverse DNSをproviderへ確認してください。
- backupにはメール本文とcredential hashが含まれます。暗号化・アクセス制御・復旧試験が必要です。
- queue一覧や管理APIからメール本文を無制限に公開しない設計です。

詳細は[security model](docs/security-model.md)、[threat model](docs/threat-model.md)、[architecture](docs/architecture.md)、[RFC matrix](docs/rfc-matrix.md)、[OpenAPI](openapi/mail-admin-api.yaml)を参照してください。
