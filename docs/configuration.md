# Configuration

`maild`は任意のTOMLファイルと、後方互換の環境変数設定を読み込みます。外部secret manager adapterは未実装です。

設定ファイルは次のいずれかで指定します。

```console
maild --config /etc/maild/maild.toml
MAIL_CONFIG_FILE=/etc/maild/maild.toml maild
```

`--config`と`MAIL_CONFIG_FILE`を両方指定した場合、`--config`を使用します。個々の設定値の優先順位は次のとおりです。

```text
環境変数 > TOMLファイル > デフォルト値
```

設定ファイルを指定しない従来の環境変数のみの起動方法も引き続き利用できます。未知のTOMLキー、読み込めないファイル、無効なsocket address、片方しか指定されていない手動TLS鍵は起動エラーになります。

## TOML schema

現在の`maild`が読み込む完全なschemaは次のとおりです。各listenerは現行実装に合わせて単一のsocket addressを取ります。

```toml
hostname = "mail.example.com"

[database]
url = "postgresql://maild@127.0.0.1/maild"

[tls]
certificate_file = "/run/secrets/maild/fullchain.pem"
private_key_file = "/run/secrets/maild/privkey.pem"

[smtp]
listen = "0.0.0.0:25"
data_progress_grace_seconds = 30
data_min_bytes_per_second = 256

[submission]
listen = "0.0.0.0:587"

[submissions]
listen = "0.0.0.0:465"

[imap]
listen = "0.0.0.0:143"

[imaps]
listen = "0.0.0.0:993"

[admin_api]
listen = "127.0.0.1:8443"
```

手動証明書を使わずACMEを使う場合は`[tls]`の代わりに次を設定します。

```toml
hostname = "mail.example.com"

[database]
url = "postgresql://maild@127.0.0.1/maild"

[acme]
domains = ["mail.example.com", "smtp.example.com", "imap.example.com"]
contacts = ["mailto:postmaster@example.com"]
cache_key_hex = "64桁のランダムなhex文字列"
production = false
listen = "0.0.0.0:443"
```

`hostname`を省略した場合は最初のACME domainを使用します。手動TLSでは`hostname`が必須です。`[tls]`が完全に設定されている場合、ACME listenerは起動しません。

## Environment overrides

| 環境変数 | TOML | default |
| --- | --- | --- |
| `MAIL_DATABASE_URL` | `database.url` | 必須 |
| `MAIL_HOSTNAME` | `hostname` | 最初のACME domain |
| `MAIL_TLS_CERT_FILE` | `tls.certificate_file` | なし |
| `MAIL_TLS_KEY_FILE` | `tls.private_key_file` | なし |
| `MAIL_ACME_DOMAINS` | `acme.domains` | ACME時は必須 |
| `MAIL_ACME_CONTACTS` | `acme.contacts` | ACME時は必須 |
| `MAIL_ACME_CACHE_KEY_HEX` | `acme.cache_key_hex` | ACME時は必須 |
| `MAIL_ACME_PRODUCTION` | `acme.production` | `false` |
| `MAIL_ACME_LISTEN` | `acme.listen` | `0.0.0.0:443` |
| `MAIL_SMTP_LISTEN` | `smtp.listen` | `0.0.0.0:25` |
| `MAIL_SMTP_DATA_PROGRESS_GRACE_SECONDS` | `smtp.data_progress_grace_seconds` | `30` |
| `MAIL_SMTP_DATA_MIN_BYTES_PER_SECOND` | `smtp.data_min_bytes_per_second` | `256` |
| `MAIL_SUBMISSION_LISTEN` | `submission.listen` | `0.0.0.0:587` |
| `MAIL_SUBMISSIONS_LISTEN` | `submissions.listen` | `0.0.0.0:465` |
| `MAIL_IMAP_LISTEN` | `imap.listen` | `0.0.0.0:143` |
| `MAIL_IMAPS_LISTEN` | `imaps.listen` | `0.0.0.0:993` |
| `MAIL_ADMIN_LISTEN` | `admin_api.listen` | `127.0.0.1:8443` |

カンマ区切りの`MAIL_ACME_DOMAINS`と`MAIL_ACME_CONTACTS`は、TOML配列全体を置き換えます。`MAIL_ACME_PRODUCTION=true`でproduction directoryを選択し、それ以外または未指定ではstagingを使います。

## Environment-only compatibility

従来と同じ起動方法は変更されていません。

```console
export MAIL_DATABASE_URL='postgresql://maild@127.0.0.1/maild'
export MAIL_ACME_DOMAINS='mail.example.com,smtp.example.com,imap.example.com'
export MAIL_ACME_CONTACTS='mailto:postmaster@example.com'
export MAIL_ACME_CACHE_KEY_HEX='64桁のランダムなhex文字列'
export MAIL_HOSTNAME='mail.example.com'
maild
```

## Secret handling

この変更はVault等の外部secret manager adapterを実装しません。DB URL、ACME cache key、private key pathをTOMLへ記載する場合は、設定ファイルをmaild実行ユーザーだけが読める権限にしてください。秘密値は可能な限り環境変数、systemd credentials、Docker/Kubernetes secretsから環境へ注入してください。private key本体はTOMLへ埋め込まずファイルパスで指定します。

相対的な証明書パスは`maild`のcurrent working directoryから解決されます。`mail-migrate up`を明示的に実行してください。`maild`はmigration compatibilityを確認し、不一致なら起動を拒否します。
