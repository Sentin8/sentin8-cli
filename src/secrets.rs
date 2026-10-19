// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! `sentin8-cli secrets` - tenant secret management (Phase 34, design §7).
//!
//! Values are accepted only from `--value-file` / `--value-env` - NEVER
//! from argv (shell history / process-list leakage). The `resolve` action
//! doubles as the security-audit stale-reference checker.

use crate::auth;
use crate::config::Sentin8Config;

#[derive(Debug, clap::Subcommand)]
pub enum SecretsCommand {
    /// List secret metadata (names, versions, status - never values).
    List {
        /// Target environment ID (defaults to config defaultEnvId or system env).
        #[arg(long)]
        env: Option<String>,
        /// Status filter: active (default) | disabled | all.
        #[arg(long, default_value = "active")]
        status: String,
    },
    /// Store a secret (upsert + new version). Value from file or env only.
    Put {
        /// Secret name path (e.g. stripe/api_key).
        #[arg(long)]
        name: String,
        /// Read the value from this file (use `-` for stdin).
        #[arg(long, group = "value_source")]
        value_file: Option<String>,
        /// Read the value from this environment variable.
        #[arg(long, group = "value_source")]
        value_env: Option<String>,
        #[arg(long)]
        description: Option<String>,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
    /// Rotate a secret (new version). Value from file or env only.
    Rotate {
        #[arg(long)]
        name: String,
        #[arg(long, group = "value_source")]
        value_file: Option<String>,
        #[arg(long, group = "value_source")]
        value_env: Option<String>,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
    /// Get secret metadata (no value).
    Get {
        #[arg(long)]
        name: String,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
    /// Resolve a secret reference URI to its value (security-audit
    /// verification command - also surfaces stale references).
    Resolve {
        /// Reference URI (e.g. secrets://stripe/api_key).
        #[arg(long)]
        r#ref: String,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
    /// Disable a secret (soft delete).
    Delete {
        #[arg(long)]
        name: String,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
    /// Show the reveal audit trail for a secret.
    Reads {
        #[arg(long)]
        name: String,
        /// Target environment ID.
        #[arg(long)]
        env: Option<String>,
    },
}

/// Resolve the secrets service base URL from the runtime registry (zero
/// hardcoded URLs - same lookup as `call.rs`).
async fn resolve_base_url(pool: &sqlx::PgPool) -> anyhow::Result<String> {
    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT subdomain FROM vertical_services
         WHERE service_type = $1 OR service_type = $2
         ORDER BY CASE WHEN service_type = $2 THEN 0 ELSE 1 END
         LIMIT 1",
    )
    .bind("sentin8:secrets")
    .bind("secrets")
    .fetch_optional(pool)
    .await?;
    let subdomain = row.map(|(h,)| h).unwrap_or_else(|| "secrets".to_string());
    Ok(format!("https://{}.ops.sys.{}", subdomain, sentin8_domain))
}

async fn resolve_target_env(env: Option<&str>) -> anyhow::Result<String> {
    let config = Sentin8Config::load();
    Ok(env
        .map(String::from)
        .or(config.default_env_id.clone())
        .unwrap_or_else(|| "00000000-0000-0000-0000-000000000002".to_string()))
}

async fn http() -> anyhow::Result<reqwest::Client> {
    let _ = rustls_graviola::default_provider().install_default();
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?)
}

/// Dispatch a secrets CLI action.
pub async fn run(command: SecretsCommand) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let (action, name, env, body) = match command {
        SecretsCommand::List { env, status } => {
            let target_env = resolve_target_env(env.as_deref()).await?;
            (
                "GET",
                None,
                target_env,
                Some(serde_json::json!({ "status": status })),
            )
        }
        SecretsCommand::Get { name, env } => {
            let target_env = resolve_target_env(env.as_deref()).await?;
            ("GET", Some(name), target_env, None)
        }
        SecretsCommand::Reads { name, env } => {
            let target_env = resolve_target_env(env.as_deref()).await?;
            ("READS", Some(name), target_env, None)
        }
        SecretsCommand::Put {
            name,
            value_file,
            value_env,
            description,
            env,
        } => {
            let value = read_value(value_file.as_deref(), value_env.as_deref())?;
            let target_env = resolve_target_env(env.as_deref()).await?;
            (
                "PUT",
                Some(name),
                target_env,
                Some(serde_json::json!({
                    "value": value,
                    "description": description.unwrap_or_default(),
                })),
            )
        }
        SecretsCommand::Rotate {
            name,
            value_file,
            value_env,
            env,
        } => {
            let value = read_value(value_file.as_deref(), value_env.as_deref())?;
            let target_env = resolve_target_env(env.as_deref()).await?;
            (
                "ROTATE",
                Some(name),
                target_env,
                Some(serde_json::json!({ "value": value })),
            )
        }
        SecretsCommand::Resolve { r#ref, env } => {
            let target_env = resolve_target_env(env.as_deref()).await?;
            (
                "RESOLVE",
                None,
                target_env,
                Some(serde_json::json!({ "ref": r#ref })),
            )
        }
        SecretsCommand::Delete { name, env } => {
            let target_env = resolve_target_env(env.as_deref()).await?;
            ("DELETE", Some(name), target_env, None)
        }
    };

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;
    let base_url = resolve_base_url(&pool).await?;
    let token = auth::get_valid_token().await?;

    // Resolve + masking note: resolve prints only whether it resolves and
    // the version - the value itself is never printed (audit hygiene).
    let (method, path) = match action {
        "GET" => ("GET", format!("/v1/secrets/{}", name.unwrap_or_default())),
        "READS" => (
            "GET",
            format!("/v1/secrets/{}/reads", name.unwrap_or_default()),
        ),
        "PUT" => ("PUT", format!("/v1/secrets/{}", name.unwrap_or_default())),
        "ROTATE" => (
            "POST",
            format!("/v1/secrets/{}/rotate", name.unwrap_or_default()),
        ),
        "DELETE" => (
            "DELETE",
            format!("/v1/secrets/{}", name.unwrap_or_default()),
        ),
        "RESOLVE" => ("POST", "/v1/secrets/resolve".to_string()),
        _ => anyhow::bail!("internal: unknown action {action}"),
    };

    let url = format!(
        "{}{}{}target_env_id={}",
        base_url,
        path,
        if path.contains('?') { '&' } else { '?' },
        env
    );

    let req = match method {
        "GET" => reqwest::Client::new().get(&url),
        "DELETE" => reqwest::Client::new().delete(&url),
        "PUT" => reqwest::Client::new()
            .put(&url)
            .json(&body.unwrap_or(serde_json::json!({}))),
        "POST" => reqwest::Client::new()
            .post(&url)
            .json(&body.unwrap_or(serde_json::json!({}))),
        _ => anyhow::bail!("unsupported method {method}"),
    }
    .bearer_auth(&token)
    .header("X-Sentin8-Env-Id", &env);

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .unwrap_or_else(|_| "(no body)".to_string());

    if !status.is_success() {
        eprintln!("Error: HTTP {status}");
        eprintln!("{text}");
        anyhow::bail!("request failed: HTTP {status}");
    }

    // `resolve` masks the value - print resolution status only (the CLI
    // operator surface never echoes secrets; use the service API directly
    // for programmatic resolution).
    if action == "RESOLVE" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            println!(
                "resolves OK (version {}); value not printed by design",
                v["version"]
            );
            return Ok(());
        }
    }

    println!("{text}");
    Ok(())
}

/// Read the secret value from file (`-` = stdin) or env var. Never argv.
fn read_value(value_file: Option<&str>, value_env: Option<&str>) -> anyhow::Result<String> {
    if let Some(file) = value_file {
        let v = if file == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        } else {
            std::fs::read_to_string(file)?
        };
        return Ok(v);
    }
    if let Some(env_key) = value_env {
        return std::env::var(env_key).map_err(|_| anyhow::anyhow!("env var {env_key} not set"));
    }
    anyhow::bail!(
        "provide exactly one of --value-file or --value-env (values are never accepted on argv)"
    )
}
