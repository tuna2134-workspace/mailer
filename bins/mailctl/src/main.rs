#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use mail_admin_client::Client;
use serde_json::Value;
use std::io::Read;

#[derive(Parser)]
#[command(about = "Mail administration API client")]
struct Cli {
    #[arg(long, env = "MAIL_API_URL", default_value = "https://127.0.0.1:8443")]
    api_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    Alias {
        #[command(subcommand)]
        command: ResourceCommand,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Config {
        #[command(subcommand)]
        command: CheckCommand,
    },
    Database {
        #[command(subcommand)]
        command: CheckCommand,
    },
    Migration {
        #[command(subcommand)]
        command: StatusCommand,
    },
    Rfc {
        #[command(subcommand)]
        command: StatusCommand,
    },
    Conformance {
        #[command(subcommand)]
        command: ReportCommand,
    },
}

#[derive(Subcommand)]
enum TenantCommand {
    List,
    Create,
    Show { tenant_id: String },
    Update { tenant_id: String, version: String },
    Disable { tenant_id: String, version: String },
}
#[derive(Subcommand)]
enum ResourceCommand {
    List(TenantArg),
    Create,
    Show {
        tenant_id: String,
        id: String,
    },
    Update {
        tenant_id: String,
        id: String,
        version: String,
    },
    Delete {
        tenant_id: String,
        id: String,
        version: String,
    },
}
#[derive(Subcommand)]
enum DomainCommand {
    List(TenantArg),
    Create,
    Show {
        tenant_id: String,
        id: String,
    },
    Update {
        tenant_id: String,
        id: String,
        version: String,
    },
    Delete {
        tenant_id: String,
        id: String,
        version: String,
    },
    Enable {
        tenant_id: String,
        id: String,
        version: String,
    },
    Disable {
        tenant_id: String,
        id: String,
        version: String,
    },
    DnsRecords {
        tenant_id: String,
        id: String,
    },
    Verify {
        tenant_id: String,
        id: String,
    },
}
#[derive(Subcommand)]
enum UserCommand {
    List(TenantArg),
    Create,
    Show {
        tenant_id: String,
        id: String,
    },
    Update {
        tenant_id: String,
        id: String,
        version: String,
    },
    Delete {
        tenant_id: String,
        id: String,
        version: String,
    },
    Enable {
        tenant_id: String,
        id: String,
        version: String,
    },
    Disable {
        tenant_id: String,
        id: String,
        version: String,
    },
    Unlock {
        tenant_id: String,
        id: String,
    },
    PasswordSet {
        tenant_id: String,
        id: String,
    },
    QuotaSet {
        tenant_id: String,
        id: String,
        version: String,
    },
}
#[derive(Subcommand)]
enum TokenCommand {
    List(TenantArg),
    Create,
    Revoke { tenant_id: String, id: String },
}
#[derive(Subcommand)]
enum AuditCommand {
    List(TenantArg),
}
#[derive(Subcommand)]
enum CheckCommand {
    Check,
}
#[derive(Subcommand)]
enum StatusCommand {
    Status,
}
#[derive(Subcommand)]
enum ReportCommand {
    Report,
}
#[derive(Args)]
struct TenantArg {
    #[arg(long)]
    tenant_id: String,
}

fn stdin_json() -> Result<Value> {
    let mut input = String::new();
    std::io::stdin()
        .take(64 * 1024)
        .read_to_string(&mut input)
        .context("read JSON from stdin")?;
    serde_json::from_str(&input).context("parse JSON from stdin")
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // CLI command-to-endpoint mapping is intentionally explicit.
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let token = std::env::var("MAIL_API_TOKEN")
        .context("MAIL_API_TOKEN must come from a secret-capable environment")?;
    let client = Client::new(&cli.api_url, token)?;
    let value = match cli.command {
        Command::Tenant { command } => match command {
            TenantCommand::List => client.list("tenants", None).await?,
            TenantCommand::Create => client.create("tenants", &stdin_json()?).await?,
            TenantCommand::Show { tenant_id } => {
                client
                    .get(&format!("/api/v1/tenants/{tenant_id}"), None)
                    .await?
            }
            TenantCommand::Update { tenant_id, version } => {
                client
                    .patch(
                        &format!("/api/v1/tenants/{tenant_id}"),
                        None,
                        &version,
                        &stdin_json()?,
                    )
                    .await?
            }
            TenantCommand::Disable { tenant_id, version } => {
                client
                    .delete(
                        &format!("/api/v1/tenants/{tenant_id}"),
                        None,
                        Some(&version),
                    )
                    .await?
            }
        },
        Command::Domain { command } => match command {
            DomainCommand::List(arg) => client.list("domains", Some(&arg.tenant_id)).await?,
            DomainCommand::Create => client.create("domains", &stdin_json()?).await?,
            DomainCommand::Show { tenant_id, id } => {
                client
                    .get(&format!("/api/v1/domains/{id}"), Some(&tenant_id))
                    .await?
            }
            DomainCommand::Update {
                tenant_id,
                id,
                version,
            } => {
                client
                    .patch(
                        &format!("/api/v1/domains/{id}"),
                        Some(&tenant_id),
                        &version,
                        &stdin_json()?,
                    )
                    .await?
            }
            DomainCommand::Delete {
                tenant_id,
                id,
                version,
            } => {
                client
                    .delete(
                        &format!("/api/v1/domains/{id}"),
                        Some(&tenant_id),
                        Some(&version),
                    )
                    .await?
            }
            DomainCommand::Enable {
                tenant_id,
                id,
                version,
            } => {
                client
                    .action(
                        &format!("/api/v1/domains/{id}/enable"),
                        Some(&tenant_id),
                        Some(&version),
                        None,
                    )
                    .await?
            }
            DomainCommand::Disable {
                tenant_id,
                id,
                version,
            } => {
                client
                    .action(
                        &format!("/api/v1/domains/{id}/disable"),
                        Some(&tenant_id),
                        Some(&version),
                        None,
                    )
                    .await?
            }
            DomainCommand::DnsRecords { tenant_id, id } => {
                client
                    .get(
                        &format!("/api/v1/domains/{id}/dns-records"),
                        Some(&tenant_id),
                    )
                    .await?
            }
            DomainCommand::Verify { tenant_id, id } => {
                client
                    .action(
                        &format!("/api/v1/domains/{id}/verify"),
                        Some(&tenant_id),
                        None,
                        None,
                    )
                    .await?
            }
        },
        Command::Alias { command } => resource(&client, "aliases", command).await?,
        Command::User { command } => match command {
            UserCommand::List(arg) => client.list("users", Some(&arg.tenant_id)).await?,
            UserCommand::Create => client.create("users", &stdin_json()?).await?,
            UserCommand::Show { tenant_id, id } => {
                client
                    .get(&format!("/api/v1/users/{id}"), Some(&tenant_id))
                    .await?
            }
            UserCommand::Update {
                tenant_id,
                id,
                version,
            } => {
                client
                    .patch(
                        &format!("/api/v1/users/{id}"),
                        Some(&tenant_id),
                        &version,
                        &stdin_json()?,
                    )
                    .await?
            }
            UserCommand::Delete {
                tenant_id,
                id,
                version,
            } => {
                client
                    .delete(
                        &format!("/api/v1/users/{id}"),
                        Some(&tenant_id),
                        Some(&version),
                    )
                    .await?
            }
            UserCommand::Enable {
                tenant_id,
                id,
                version,
            } => {
                client
                    .action(
                        &format!("/api/v1/users/{id}/enable"),
                        Some(&tenant_id),
                        Some(&version),
                        None,
                    )
                    .await?
            }
            UserCommand::Disable {
                tenant_id,
                id,
                version,
            } => {
                client
                    .action(
                        &format!("/api/v1/users/{id}/disable"),
                        Some(&tenant_id),
                        Some(&version),
                        None,
                    )
                    .await?
            }
            UserCommand::Unlock { tenant_id, id } => {
                client
                    .action(
                        &format!("/api/v1/users/{id}/unlock"),
                        Some(&tenant_id),
                        None,
                        None,
                    )
                    .await?
            }
            UserCommand::PasswordSet { tenant_id, id } => {
                client
                    .action(
                        &format!("/api/v1/users/{id}/password"),
                        Some(&tenant_id),
                        None,
                        Some(&stdin_json()?),
                    )
                    .await?
            }
            UserCommand::QuotaSet {
                tenant_id,
                id,
                version,
            } => {
                client
                    .patch(
                        &format!("/api/v1/users/{id}/quota"),
                        Some(&tenant_id),
                        &version,
                        &stdin_json()?,
                    )
                    .await?
            }
        },
        Command::Token { command } => match command {
            TokenCommand::List(arg) => {
                client
                    .get("/api/v1/api-tokens", Some(&arg.tenant_id))
                    .await?
            }
            TokenCommand::Create => {
                client
                    .action("/api/v1/api-tokens", None, None, Some(&stdin_json()?))
                    .await?
            }
            TokenCommand::Revoke { tenant_id, id } => {
                client
                    .delete(&format!("/api/v1/api-tokens/{id}"), Some(&tenant_id), None)
                    .await?
            }
        },
        Command::Audit {
            command: AuditCommand::List(arg),
        } => client.get("/api/v1/audit", Some(&arg.tenant_id)).await?,
        Command::Config { .. }
        | Command::Database { .. }
        | Command::Migration { .. }
        | Command::Rfc { .. }
        | Command::Conformance { .. } => {
            Value::String("not exposed by the Phase 2 HTTP API".into())
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn resource(client: &Client, name: &str, command: ResourceCommand) -> Result<Value> {
    Ok(match command {
        ResourceCommand::List(arg) => client.list(name, Some(&arg.tenant_id)).await?,
        ResourceCommand::Create => client.create(name, &stdin_json()?).await?,
        ResourceCommand::Show { tenant_id, id } => {
            client
                .get(&format!("/api/v1/{name}/{id}"), Some(&tenant_id))
                .await?
        }
        ResourceCommand::Update {
            tenant_id,
            id,
            version,
        } => {
            client
                .patch(
                    &format!("/api/v1/{name}/{id}"),
                    Some(&tenant_id),
                    &version,
                    &stdin_json()?,
                )
                .await?
        }
        ResourceCommand::Delete {
            tenant_id,
            id,
            version,
        } => {
            client
                .delete(
                    &format!("/api/v1/{name}/{id}"),
                    Some(&tenant_id),
                    Some(&version),
                )
                .await?
        }
    })
}
