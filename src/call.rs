// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Generic service passthrough - `sentin8-cli call <service> <method> <path>`.
//!
//! The escape hatch for one-off/undocumented endpoints. Resolves the service
//! URL via `sentin8_vertical_services` (runtime registry - zero hardcoded
//! URLs), sends the request with the stored token, and prints the response.
//! Requires no registry entry - useful for debugging. The declarative
//! `cli_commands` path (commands.rs) is preferred for repeated operations
//! because it carries scope + arg validation.
//! See `sentin8-sentin8-cli-technical-design.md` §9.5.

use crate::auth;
use crate::config::Sentin8Config;

/// Execute a generic passthrough call.
pub async fn execute(
    service: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    env_id: Option<&str>,
) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // 1. Resolve service URL from sentin8_vertical_services.
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;

    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".to_string());

    // Resolve by colon identity (architecture-principles.md §6.0): the
    // bare name maps to the platform identity `sentin8:{service}`, or an
    // exact/identity-suffix match in the runtime registry (e.g. `ledger`
    // → `bank8:ledger`). The hostname comes from the registry `subdomain`
    // column (DNS label) - never from the colon identity directly.
    // SAME resolution flow as commands.rs::resolve_service_url (design
    // §9.3): exact identity first, then the `:{service}` suffix - a bare
    // leaf name must resolve a vertical's colon identity, otherwise the
    // dash-less fallback builds the wrong host (`fdx.ops.sys.…` → Web
    // app-fallback 404).
    let platform_identity = format!("sentin8:{}", service);
    let suffix_pattern = format!("%:{}", service);

    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT subdomain FROM vertical_services
           WHERE service_type = $1 OR service_type = $2 OR service_type LIKE $3
           ORDER BY CASE WHEN service_type = $1 THEN 0
                         WHEN service_type = $2 THEN 1
                         ELSE 2 END
           LIMIT 1"#,
    )
    .bind(&platform_identity)
    .bind(service)
    .bind(&suffix_pattern)
    .fetch_optional(&pool)
    .await?;

    let subdomain = row.map(|(h,)| h).unwrap_or_else(|| service.to_string());
    let base_url = format!("https://{}.ops.sys.{}", subdomain, sentin8_domain);

    // 2. Resolve target env_id.
    let config = Sentin8Config::load();
    let target_env = env_id
        .map(String::from)
        .or(config.default_env_id.clone())
        .unwrap_or_else(|| "00000000-0000-0000-0000-000000000002".to_string());

    if path.contains("/v1/admin/") && env_id.is_none() && config.default_env_id.is_none() {
        anyhow::bail!("--env=<env_id> is required for admin endpoints");
    }

    // 3. Obtain token - use the user token directly. The target_env_id is
    // passed as a query param so the service resolves the correct tenant.
    // Delegation is not needed because the user token already carries the
    // required scopes (env:admin nests service-admin roles), and the
    // service handlers read target_env_id from the query param.
    let token = auth::get_valid_token().await?;

    // 4. Build URL (ensure path starts with /).
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };

    // Attach target_env_id as a query parameter so env-scoped admin APIs
    // (auth, cron, post, stat, etc.) can resolve the tenant context.
    // The X-Sentin8-Env-Id header is for sentin8-tls; the query param is
    // for the application layer (require_sentin8or_access_with_env).
    let sep = if path.contains('?') { '&' } else { '?' };
    let url = format!("{}{}{}target_env_id={}", base_url, path, sep, target_env);

    // 5. Dispatch.
    // Use a client that accepts the local self-signed CA (Sentin8:Acme).
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let method_upper = method.to_uppercase();
    let mut req = match method_upper.as_str() {
        "GET" => http.get(&url),
        "POST" => {
            let body_val = parse_body(body)?;
            http.post(&url).json(&body_val)
        }
        "PUT" => {
            let body_val = parse_body(body)?;
            http.put(&url).json(&body_val)
        }
        "DELETE" => http.delete(&url),
        "PATCH" => {
            let body_val = parse_body(body)?;
            http.patch(&url).json(&body_val)
        }
        _ => anyhow::bail!("unsupported HTTP method: {method_upper}"),
    };
    req = req.bearer_auth(&token);
    req = req.header("X-Sentin8-Env-Id", &target_env);

    let resp = req.send().await?;
    let status = resp.status();

    // Event-producer fallback (bus DESIGN §4.3, CLI-producer path): the
    // gate rejects produce from USER tokens (no `vertical` claim -
    // fail-closed). Operator tooling / e2e tests legitimately drive
    // produces: retry ONCE with the CLI's own M2M producer token
    // (`cli-producer`, vertical 'sentin8' from its grant row) when the
    // 403 body names the ownership gate. Any other failure falls through.
    if !status.is_success() {
        let retry_text = resp.text().await.unwrap_or_default();
        let ownership =
            status == reqwest::StatusCode::FORBIDDEN && retry_text.contains("event_ownership");
        if ownership {
            // the `cli-producer` CERTIFICATE is the identity -
            // the cert-presenting transport replaces the token on the retry.
            let producer_http =
                crate::auth::get_cli_producer_transport(&crate::config::sentin8_auth_url()).await?;
            let body_val = parse_body(body)?;
            let mut retry_req = match method_upper.as_str() {
                "POST" => producer_http.post(&url).json(&body_val),
                "PUT" => producer_http.put(&url).json(&body_val),
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

fn parse_body(body: Option<&str>) -> anyhow::Result<serde_json::Value> {
    match body {
        Some(b) => serde_json::from_str(b).map_err(|e| anyhow::anyhow!("invalid JSON body: {e}")),
        None => Ok(serde_json::json!({})),
    }
}
