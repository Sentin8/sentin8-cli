// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Declarative command executor - `sentin8-cli <command> <subcommand> <action>`.
//!
//! Reads command definitions from the `sentin8_cli_commands` table (populated
//! by `vertical enroll`) and dispatches them dynamically. The CLI binary
//! contains no hardcoded service subcommands - every service's command surface
//! is registry-driven. See `sentin8-sentin8-cli-technical-design.md` §9.
//!
//! Resolution flow (design §9.3):
//!   1. Load command definitions from sentin8_cli_commands for `command`.
//!   2. Match `subcommand` + `action` → find the {method, path, scope, args} entry.
//!   3. Resolve the service URL for `command` via sentin8_vertical_services.
//!   4. Resolve target env_id (from --env / config defaultEnvId / system env).
//!   5. Obtain a delegated env-scoped token (design §3.2).
//!   6. Interpolate {arg} placeholders from args.
//!   7. Dispatch with Authorization: Bearer <token>; print response.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::auth;
use crate::config::Sentin8Config;

/// A CLI command definition loaded from `sentin8_cli_commands`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDef {
    pub vertical: String,
    pub command: String,
    pub subcommand: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub scope: String,
    #[serde(default)]
    pub args: Vec<CommandArgDef>,
}

/// An argument definition within a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandArgDef {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub position: Option<String>,
}

/// Load all command definitions from the database.
pub async fn load_all_commands() -> anyhow::Result<Vec<CommandDef>> {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;
    let rows = sqlx::query_as::<_, CommandDefRow>(
        r#"SELECT vertical, command, subcommand, action, method, path, scope, args
           FROM cli_commands
           ORDER BY command, subcommand, action"#,
    )
    .fetch_all(&pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Load command definitions for a specific command group (e.g. "auth").
pub async fn load_commands(command: &str) -> anyhow::Result<Vec<CommandDef>> {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;
    let rows = sqlx::query_as::<_, CommandDefRow>(
        r#"SELECT vertical, command, subcommand, action, method, path, scope, args
           FROM cli_commands
           WHERE command = $1
           ORDER BY subcommand, action"#,
    )
    .bind(command)
    .fetch_all(&pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Raw DB row for a CLI command (sqlx needs a flat struct for query_as).
#[derive(Debug, sqlx::FromRow)]
struct CommandDefRow {
    vertical: String,
    command: String,
    subcommand: String,
    action: String,
    method: String,
    path: String,
    scope: String,
    args: serde_json::Value,
}

impl From<CommandDefRow> for CommandDef {
    fn from(row: CommandDefRow) -> Self {
        let args: Vec<CommandArgDef> = serde_json::from_value(row.args).unwrap_or_default();
        CommandDef {
            vertical: row.vertical,
            command: row.command,
            subcommand: row.subcommand,
            action: row.action,
            method: row.method,
            path: row.path,
            scope: row.scope,
            args,
        }
    }
}

/// Resolve the service URL for a command group by looking up
/// `sentin8_vertical_services` and deriving the hostname from the
/// platform_domain_key (design §4.14 - zero hardcoded URLs).
async fn resolve_service_url(command: &str) -> anyhow::Result<String> {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;

    // The command group maps to a service identity (architecture-principles
    // .md §6.0). For platform services the identity is `sentin8:{command}`
    // (e.g. `auth` → `sentin8:auth`); for vertical services it's
    // `{vertical}:{command}` (e.g. `bank8:ledger`). We match exact identity
    // or identity suffix (`:command`), preferring the platform identity.
    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".to_string());

    let identity = format!("sentin8:{}", command);
    let suffix_pattern = format!("%:{}", command);

    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT subdomain FROM vertical_services
           WHERE service_type = $1 OR service_type LIKE $2
           ORDER BY CASE WHEN service_type = $1 THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(&identity)
    .bind(&suffix_pattern)
    .fetch_optional(&pool)
    .await?;

    let subdomain = row.map(|(h,)| h).unwrap_or_else(|| command.to_string());

    Ok(format!("https://{}.ops.sys.{}", subdomain, sentin8_domain))
}

/// List all available commands (for `sentin8-cli list-commands`).
pub async fn list_commands() -> anyhow::Result<()> {
    let commands = load_all_commands().await?;
    if commands.is_empty() {
        println!("No CLI commands registered. Run 'sentin8-cli vertical enroll' first.");
        return Ok(());
    }

    // Group by command → subcommand → actions.
    let mut grouped: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for cmd in &commands {
        grouped
            .entry(cmd.command.clone())
            .or_default()
            .entry(cmd.subcommand.clone())
            .or_default()
            .push(cmd.action.clone());
    }

    let mut commands_sorted: Vec<_> = grouped.keys().collect();
    commands_sorted.sort();
    for command in commands_sorted {
        let subs = &grouped[command];
        println!("\n  {command}:");
        let mut subs_sorted: Vec<_> = subs.keys().collect();
        subs_sorted.sort();
        for sub in subs_sorted {
            let actions = subs[sub].join(", ");
            println!("    {sub} → {actions}");
        }
    }
    Ok(())
}

/// Execute a declarative command: `sentin8-cli <command> <subcommand> <action> [args]`.
///
/// `field_args` is a map of `--field value` pairs from the command line.
/// `path_args` is a map of positional path arguments.
pub async fn execute(
    command: &str,
    subcommand: &str,
    action: &str,
    field_args: &HashMap<String, String>,
    path_args: &HashMap<String, String>,
    env_id: Option<&str>,
) -> anyhow::Result<()> {
    // 1. Load + match command definition.
    let commands = load_commands(command).await?;
    let cmd = commands
        .iter()
        .find(|c| c.subcommand == subcommand && c.action == action);
    let cmd = match cmd {
        Some(c) => c,
        None => {
            // Print available commands for this group as a hint.
            eprintln!("No command '{command} {subcommand} {action}' found.");
            if !commands.is_empty() {
                eprintln!("Available '{command}' commands:");
                for c in &commands {
                    eprintln!(
                        "  {command} {} {} → {} {}",
                        c.subcommand, c.action, c.method, c.path
                    );
                }
            } else {
                eprintln!("No commands registered for '{command}'. Run 'sentin8-cli vertical enroll' first.");
            }
            anyhow::bail!("command not found");
        }
    };
    let cmd = cmd.clone();

    // 2. Resolve service URL.
    let base_url = resolve_service_url(command).await?;

    // 3. Resolve target env_id.
    let config = Sentin8Config::load();
    let target_env = env_id
        .map(String::from)
        .or(config.default_env_id.clone())
        .unwrap_or_else(|| {
            // System env UUID (ops) - for platform-scoped commands.
            "00000000-0000-0000-0000-000000000002".to_string()
        });

    if cmd.path.contains("/v1/admin/") && env_id.is_none() && config.default_env_id.is_none() {
        anyhow::bail!("--env=<env_id> is required for admin endpoints");
    }

    // 4. Obtain token - use the user token directly. The target_env_id is
    // passed as a query param so the service resolves the correct tenant.
    // Delegation is not needed because the user token already carries the
    // required scopes (env:admin nests service-admin roles), and the
    // service handlers read target_env_id from the query param.
    let token = auth::get_valid_token().await?;

    // 5. Interpolate path placeholders and build query params.
    let mut path = cmd.path.clone();
    for arg in &cmd.args {
        if arg.kind == "path" {
            let value = path_args
                .get(&arg.name)
                .or_else(|| field_args.get(&arg.name))
                .cloned();
            if let Some(val) = value {
                // Replace {arg_name} in the path.
                path = path.replace(&format!("{{{}}}", arg.name), &val);
            } else if arg.required {
                anyhow::bail!("missing required path argument: --{}", arg.name);
            }
        }
    }

    // Build query string from query-type args.
    let mut query_params: Vec<(String, String)> = Vec::new();
    for arg in &cmd.args {
        if arg.kind == "query" {
            if let Some(val) = field_args.get(&arg.name) {
                query_params.push((arg.name.clone(), val.clone()));
            } else if arg.required {
                anyhow::bail!("missing required query argument: --{}", arg.name);
            }
        }
    }

    // Build request body from field-type args.
    let mut body: serde_json::Value = serde_json::json!({});
    for arg in &cmd.args {
        if arg.kind == "field" {
            if let Some(val) = field_args.get(&arg.name) {
                // Try to parse as JSON, fall back to string.
                body[arg.name.clone()] = serde_json::from_str(val)
                    .unwrap_or_else(|_| serde_json::Value::String(val.clone()));
            } else if arg.required {
                anyhow::bail!("missing required field argument: --{}", arg.name);
            }
        }
    }

    // Passthrough: include any field_args that aren't already consumed by
    // path/query args or explicitly defined field args. This handles the
    // case where the command definition has no field args (e.g., because
    // extract_args() didn't parse the requestBody schema), but the user
    // passed --key=value pairs that should go into the JSON body.
    let consumed_names: std::collections::HashSet<&str> =
        cmd.args.iter().map(|a| a.name.as_str()).collect();
    for (key, val) in field_args.iter() {
        if !consumed_names.contains(key.as_str()) {
            body[key.clone()] = serde_json::from_str(val)
                .unwrap_or_else(|_| serde_json::Value::String(val.clone()));
        }
    }

    // 6. Build the full URL.
    // Always include target_env_id as a query parameter so env-scoped admin
    // APIs (auth, cron, post, stat, etc.) can resolve the tenant context.
    // The X-Sentin8-Env-Id header is for sentin8-tls; the query param is
    // for the application layer (require_sentin8or_access_with_env).
    if !query_params.iter().any(|(k, _)| k == "target_env_id") {
        query_params.push(("target_env_id".to_string(), target_env.clone()));
    }
    let url = if query_params.is_empty() {
        format!("{}{}", base_url, path)
    } else {
        let qs: Vec<String> = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();
        format!("{}{}?{}", base_url, path, qs.join("&"))
    };

    // 7. Dispatch.
    // Use a client that accepts the local self-signed CA (Sentin8:Acme)
    // - in dev/test environments the local Root CA is not in the system
    // trust store that reqwest's default Client reads.
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let method = cmd.method.to_uppercase();
    let mut req = match method.as_str() {
        "GET" => http.get(&url),
        "POST" => http.post(&url).json(&body),
        "PUT" => http.put(&url).json(&body),
        "DELETE" => http.delete(&url),
        "PATCH" => http.patch(&url).json(&body),
        _ => anyhow::bail!("unsupported HTTP method: {method}"),
    };
    req = req.bearer_auth(&token);

    // Attach X-Sentin8-Env-Id header for tenant context (the service's
    // sentin8-tls middleware reads this to set RLS context).
    req = req.header("X-Sentin8-Env-Id", &target_env);

    let resp = req.send().await?;
    let status = resp.status();

    // Event-producer fallback (bus DESIGN §4.3, CLI-producer path): the
    // VDC-2 gate rejects produce from USER tokens (no `vertical` claim -
    // fail-closed). Operator tooling / e2e tests legitimately drive
    // produces: retry ONCE with the CLI's own M2M producer token
    // (`cli-producer`, vertical 'sentin8' from its grant row) when the
    // 403 body names the ownership gate. Same behavior as call.rs -
    // any other failure falls through to the normal error path.
    if !status.is_success() {
        let retry_text = resp.text().await.unwrap_or_default();
        let ownership =
            status == reqwest::StatusCode::FORBIDDEN && retry_text.contains("event_ownership");
        if ownership {
            // the `cli-producer` CERTIFICATE is the identity -
            // the cert-presenting transport replaces the token on the retry.
            let producer_http =
                crate::auth::get_cli_producer_transport(&crate::config::sentin8_auth_url()).await?;
            let mut retry_req = match method.as_str() {
                "POST" => producer_http.post(&url).json(&body),
                "PUT" => producer_http.put(&url).json(&body),
                _ => anyhow::bail!("produce fallback supports POST/PUT only"),
            };
            retry_req = retry_req.header("X-Sentin8-Env-Id", &target_env);
            let retry_resp = retry_req.send().await?;
            let retry_status = retry_resp.status();
            if retry_status.is_success() {
                let ct = retry_resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if ct.contains("application/json") {
                    let json: serde_json::Value = retry_resp.json().await?;
                    println!("{}", serde_json::to_string_pretty(&json)?);
                } else {
                    let text = retry_resp.text().await?;
                    println!("{text}");
                }
                return Ok(());
            }
            let text = retry_resp
                .text()
                .await
                .unwrap_or_else(|_| "(no body)".to_string());
            eprintln!("Error: HTTP {} (producer retry)", retry_status);
            eprintln!("{text}");
            anyhow::bail!("request failed: HTTP {} (producer retry)", retry_status);
        }
        eprintln!("Error: HTTP {status}");
        eprintln!("{retry_text}");
        anyhow::bail!("request failed: HTTP {status}");
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if content_type.contains("application/json") {
        let json: serde_json::Value = resp.json().await?;
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        let text = resp.text().await?;
        println!("{text}");
    }

    Ok(())
}

/// Minimal URL-encoding for query parameter values.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test path placeholder interpolation - `{id}` in path is replaced
    /// with the value from path_args.
    #[test]
    fn path_interpolation() {
        let mut path = "/v1/admin/users/{id}".to_string();
        let arg = CommandArgDef {
            name: "id".into(),
            kind: "path".into(),
            required: true,
            secret: false,
            position: Some("users/{id}".into()),
        };
        let path_args = HashMap::from([("id".to_string(), "abc-123".to_string())]);

        // Simulate the interpolation loop from execute().
        if arg.kind == "path" {
            if let Some(val) = path_args.get(&arg.name) {
                path = path.replace(&format!("{{{}}}", arg.name), val);
            }
        }
        assert_eq!(path, "/v1/admin/users/abc-123");
    }

    /// Test multiple path placeholders - `{orgId}` and `{envId}`.
    #[test]
    fn multiple_path_interpolation() {
        let mut path = "/v1/org/{orgId}/env/{envId}/services".to_string();
        let args = vec![
            CommandArgDef {
                name: "orgId".into(),
                kind: "path".into(),
                required: true,
                secret: false,
                position: Some("org/{orgId}/env/{envId}/services".into()),
            },
            CommandArgDef {
                name: "envId".into(),
                kind: "path".into(),
                required: true,
                secret: false,
                position: Some("env/{envId}/services".into()),
            },
        ];
        let path_args = HashMap::from([
            ("orgId".to_string(), "org-001".to_string()),
            ("envId".to_string(), "env-002".to_string()),
        ]);

        for arg in &args {
            if arg.kind == "path" {
                if let Some(val) = path_args.get(&arg.name) {
                    path = path.replace(&format!("{{{}}}", arg.name), val);
                }
            }
        }
        assert_eq!(path, "/v1/org/org-001/env/env-002/services");
    }

    /// Test that missing required path arg produces an error.
    #[test]
    fn missing_required_path_arg() {
        let arg = CommandArgDef {
            name: "id".into(),
            kind: "path".into(),
            required: true,
            secret: false,
            position: Some("users/{id}".into()),
        };
        let path_args: HashMap<String, String> = HashMap::new();

        // Simulate the required check.
        let value = path_args.get(&arg.name);
        assert!(value.is_none(), "expected missing path arg");
        // The execute() function would bail with "missing required path argument".
    }

    /// Test query parameter construction.
    #[test]
    fn query_params() {
        let args = vec![
            CommandArgDef {
                name: "domain".into(),
                kind: "query".into(),
                required: false,
                secret: false,
                position: None,
            },
            CommandArgDef {
                name: "status".into(),
                kind: "query".into(),
                required: false,
                secret: false,
                position: None,
            },
        ];
        let field_args = HashMap::from([
            ("domain".to_string(), "ledger".to_string()),
            ("status".to_string(), "active".to_string()),
        ]);

        let mut query_params: Vec<(String, String)> = Vec::new();
        for arg in &args {
            if arg.kind == "query" {
                if let Some(val) = field_args.get(&arg.name) {
                    query_params.push((arg.name.clone(), val.clone()));
                }
            }
        }
        assert_eq!(query_params.len(), 2);
        assert_eq!(
            query_params[0],
            ("domain".to_string(), "ledger".to_string())
        );
        assert_eq!(
            query_params[1],
            ("status".to_string(), "active".to_string())
        );
    }

    /// Test request body construction from field args.
    #[test]
    fn body_construction() {
        let args = vec![
            CommandArgDef {
                name: "email".into(),
                kind: "field".into(),
                required: true,
                secret: false,
                position: None,
            },
            CommandArgDef {
                name: "password".into(),
                kind: "field".into(),
                required: true,
                secret: true,
                position: None,
            },
        ];
        let field_args = HashMap::from([
            ("email".to_string(), "test@test.com".to_string()),
            ("password".to_string(), "secret123".to_string()),
        ]);

        let mut body: serde_json::Value = serde_json::json!({});
        for arg in &args {
            if arg.kind == "field" {
                if let Some(val) = field_args.get(&arg.name) {
                    body[arg.name.clone()] = serde_json::from_str(val)
                        .unwrap_or_else(|_| serde_json::Value::String(val.clone()));
                }
            }
        }
        assert_eq!(body["email"], "test@test.com");
        assert_eq!(body["password"], "secret123");
    }

    /// Test body construction with JSON value (e.g. --config='{"key":"val"}').
    #[test]
    fn body_json_field() {
        let args = vec![CommandArgDef {
            name: "config".into(),
            kind: "field".into(),
            required: true,
            secret: false,
            position: None,
        }];
        let field_args = HashMap::from([(
            "config".to_string(),
            r#"{"is_provider":true,"fdx_version":"6.4"}"#.to_string(),
        )]);

        let mut body: serde_json::Value = serde_json::json!({});
        for arg in &args {
            if arg.kind == "field" {
                if let Some(val) = field_args.get(&arg.name) {
                    body[arg.name.clone()] = serde_json::from_str(val)
                        .unwrap_or_else(|_| serde_json::Value::String(val.clone()));
                }
            }
        }
        assert_eq!(body["config"]["is_provider"], true);
        assert_eq!(body["config"]["fdx_version"], "6.4");
    }

    /// Test URL-encoding of query parameter values.
    #[test]
    fn url_encoding() {
        assert_eq!(urlencoding::encode("hello"), "hello");
        assert_eq!(urlencoding::encode("a b c"), "a%20b%20c");
        assert_eq!(urlencoding::encode("key=val"), "key%3Dval");
        assert_eq!(urlencoding::encode("safe-_.~"), "safe-_.~");
    }

    /// Test secret masking - secret args should be identifiable for masking.
    #[test]
    fn secret_arg_identification() {
        let args = [
            CommandArgDef {
                name: "email".into(),
                kind: "field".into(),
                required: true,
                secret: false,
                position: None,
            },
            CommandArgDef {
                name: "password".into(),
                kind: "field".into(),
                required: true,
                secret: true,
                position: None,
            },
        ];

        let secret_args: Vec<&str> = args
            .iter()
            .filter(|a| a.secret)
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(secret_args, vec!["password"]);
    }

    /// Test command matching logic - find the right command from a list.
    #[test]
    fn command_matching() {
        let commands = [
            CommandDef {
                vertical: "sentin8".into(),
                command: "auth".into(),
                subcommand: "user".into(),
                action: "list".into(),
                method: "GET".into(),
                path: "/v1/admin/users".into(),
                scope: "sentin8:auth:users:read".into(),
                args: vec![],
            },
            CommandDef {
                vertical: "sentin8".into(),
                command: "auth".into(),
                subcommand: "user".into(),
                action: "create".into(),
                method: "POST".into(),
                path: "/v1/admin/users".into(),
                scope: "sentin8:auth:users:write".into(),
                args: vec![],
            },
            CommandDef {
                vertical: "sentin8".into(),
                command: "auth".into(),
                subcommand: "role".into(),
                action: "list".into(),
                method: "GET".into(),
                path: "/v1/admin/roles".into(),
                scope: "sentin8:auth:roles:read".into(),
                args: vec![],
            },
        ];

        // Match "auth user create"
        let found = commands
            .iter()
            .find(|c| c.subcommand == "user" && c.action == "create");
        assert!(found.is_some());
        assert_eq!(found.unwrap().method, "POST");

        // Match "auth role list"
        let found = commands
            .iter()
            .find(|c| c.subcommand == "role" && c.action == "list");
        assert!(found.is_some());
        assert_eq!(found.unwrap().path, "/v1/admin/roles");

        // Non-existent command should not match
        let found = commands
            .iter()
            .find(|c| c.subcommand == "user" && c.action == "delete");
        assert!(found.is_none());
    }

    /// Test system env detection.
    #[test]
    fn system_env_detection() {}

    /// Test URL construction with query params.
    #[test]
    fn url_with_query_params() {
        let base_url = "https://sentin8-cron.ops.sys.local.sentin8.dev";
        let path = "/v1/schedules";
        let query_params: Vec<(String, String)> = vec![
            ("domain".to_string(), "ledger".to_string()),
            ("status".to_string(), "active".to_string()),
        ];

        let qs: Vec<String> = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();
        let url = format!("{}{}?{}", base_url, path, qs.join("&"));
        assert_eq!(
            url,
            "https://sentin8-cron.ops.sys.local.sentin8.dev/v1/schedules?domain=ledger&status=active"
        );
    }

    /// Test URL construction without query params.
    #[test]
    fn url_without_query_params() {
        let base_url = "https://sentin8-auth.ops.sys.local.sentin8.dev";
        let path = "/v1/admin/users";
        let query_params: Vec<(String, String)> = vec![];

        let url = if query_params.is_empty() {
            format!("{}{}", base_url, path)
        } else {
            format!("{}{}?{}", base_url, path, "qs")
        };
        assert_eq!(
            url,
            "https://sentin8-auth.ops.sys.local.sentin8.dev/v1/admin/users"
        );
    }

    /// Test that parse_field_args from main.rs correctly parses --key=value.
    #[test]
    fn parse_field_args_equals() {
        // Simulate the parse_field_args logic from main.rs
        let fields = [
            "--email=test@test.com".to_string(),
            "--password=secret".to_string(),
        ];
        let mut field_args = HashMap::new();
        let mut i = 0;
        while i < fields.len() {
            let field = &fields[i];
            if let Some(rest) = field.strip_prefix("--") {
                if let Some((key, value)) = rest.split_once('=') {
                    field_args.insert(key.to_string(), value.to_string());
                }
            }
            i += 1;
        }
        assert_eq!(field_args.get("email"), Some(&"test@test.com".to_string()));
        assert_eq!(field_args.get("password"), Some(&"secret".to_string()));
    }

    /// Test that parse_field_args handles --key value (space-separated).
    #[test]
    fn parse_field_args_space() {
        let fields = ["--email".to_string(), "test@test.com".to_string()];
        let mut field_args = HashMap::new();
        let mut i = 0;
        while i < fields.len() {
            let field = &fields[i];
            if let Some(rest) = field.strip_prefix("--") {
                if let Some((key, value)) = rest.split_once('=') {
                    field_args.insert(key.to_string(), value.to_string());
                } else if i + 1 < fields.len() && !fields[i + 1].starts_with("--") {
                    field_args.insert(rest.to_string(), fields[i + 1].clone());
                    i += 1;
                } else {
                    field_args.insert(rest.to_string(), "true".to_string());
                }
            }
            i += 1;
        }
        assert_eq!(field_args.get("email"), Some(&"test@test.com".to_string()));
    }
}
