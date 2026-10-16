// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Infrastructure (PostgreSQL + Valkey) metrics for `sentin8 captain services`.
//!
//! After listing service instances, the CLI prints a compact one-line-per-
//! system summary of the backing databases. The CLI connects **directly** to
//! PostgreSQL and Valkey (using `DATABASE_URL` / `VALKEY_URL` from the
//! environment or `.env`) rather than routing through captain:
//!
//! - captain owns the Valkey service registry and intentionally has no
//!   PostgreSQL dependency — it must be able to boot and report status even
//!   when PostgreSQL is down.
//! - Querying infra from the CLI means a saturated or unreachable database
//!   still renders as a readable "unreachable (...)" line instead of
//!   breaking the supervisor or hiding the problem (this is exactly the kind
//!   of signal that surfaces connection-pool exhaustion early).
//!
//! Every error degrades to a short line: `make status` must never abort
//! because a backend is down.

use std::time::Duration;

use sqlx::Connection;

/// Timeout for each infra probe. Kept short so a down backend doesn't stall
/// the status command.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Pretty-print a one-line-per-system infrastructure summary.
pub async fn print_infra() {
    // Best-effort `.env` load (services do the same via dotenvy::dotenv at
    // boot). `make status` runs from the repo root where `.env` lives.
    let _ = dotenvy::dotenv();

    let pg = tokio::time::timeout(PROBE_TIMEOUT, pg_line()).await;
    let valkey = tokio::time::timeout(PROBE_TIMEOUT, valkey_line()).await;

    println!("Infrastructure:");
    match pg {
        Ok(Ok((url, line))) => println!("  PostgreSQL  {line}  {url}"),
        Ok(Err(e)) => println!("  PostgreSQL  unreachable ({})", short_err(&e)),
        Err(_) => println!("  PostgreSQL  unreachable (timeout)"),
    }
    match valkey {
        Ok(Ok((url, line))) => println!("  Valkey      {line}  {url}"),
        Ok(Err(e)) => println!("  Valkey      unreachable ({})", short_err(&e)),
        Err(_) => println!("  Valkey      unreachable (timeout)"),
    }
    // Blank line separates the infra block from the service table that follows.
    println!();
}

/// Reduce a noisy connection error to a single tidy line.
fn short_err(e: &anyhow::Error) -> String {
    let s = e.to_string();
    let first = s.split('\n').next().unwrap_or(&s);
    first.chars().take(90).collect::<String>()
}

/// Build the PostgreSQL summary line.
///
/// Returns `(masked_url, summary)` — e.g.
/// `("postgres://sentin8@host:5432/sentin8", "v18  conns 103/200 (94 idle, 51%)  db 14 MB")`.
async fn pg_line() -> anyhow::Result<(String, String)> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost/sentin8".to_string());
    let opts = sentin8::config::pg_pool::connect_options_for(&url)?;
    let mut conn = sqlx::postgres::PgConnection::connect_with(&opts).await?;

    let row: (String, i64, i64, i64, String) = sqlx::query_as(
        r#"SELECT
             current_setting('server_version')                    AS ver,
             current_setting('max_connections')::bigint           AS max_conns,
             (SELECT count(*) FROM pg_stat_activity)               AS used,
             (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle') AS idle,
             pg_size_pretty(pg_database_size(current_database()))  AS db_size
        "#,
    )
    .fetch_one(&mut conn)
    .await?;

    let (ver, max, used, idle, db_size) = row;
    let major = ver.split('.').next().unwrap_or(&ver);
    let pct = if max > 0 { used * 100 / max } else { 0 };
    let line = format!("v{major}  conns {used}/{max} ({idle} idle, {pct}%)  db {db_size}");
    Ok((mask_password(&url), line))
}

/// Build the Valkey summary line.
///
/// Returns `(masked_url, summary)` — e.g.
/// `("valkeys://host:6379/0", "v9.1  clients 23  mem 12.3M  keys 145  up 3d")`.
///
/// Connects over the certificate-identity TLS plane via Valkey GLIDE
/// with the local CONTROL identity (read-only — status probes never
/// need more; group DESIGN.md §3.1).
async fn valkey_line() -> anyhow::Result<(String, String)> {
    let url = std::env::var("VALKEY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(sentin8::config::service_valkey_url);
    let client = sentin8::middleware::valkey_client(&url, "valkey-control").await?;
    use glide::CustomCommand as _;
    let info: String = client
        .custom_command(&["INFO"])
        .await
        .and_then(|v| match v {
            // GLIDE negotiates RESP3 by default, where INFO replies as a
            // VerbatimString; RESP2 servers answer Bulk/SimpleString. Any
            // OTHER shape (int, array, error, …) means the probe did not
            // get an INFO document — surface it as a probe error instead
            // of rendering an empty summary (STATUSID-1: the silent
            // empty-string fallback made the line look connected-but-blank).
            glide::ValkeyValue::VerbatimString { text, .. } => Ok(text),
            glide::ValkeyValue::BulkString(b) => {
                Ok(String::from_utf8_lossy(&b).into_owned())
            }
            glide::ValkeyValue::SimpleString(s) => Ok(s),
            other => Err(glide::GlideError::Request(format!(
                "unexpected INFO reply type: {other:?}"
            ))),
        })
        .map_err(|e| anyhow::anyhow!("INFO: {e}"))?;

    let get = |key: &str| -> String {
        info.lines()
            .find_map(|l| {
                l.strip_prefix(&format!("{key}:"))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_default()
    };

    let version = {
        // Valkey reports `valkey_version` (the actual engine version).
        let full = get("valkey_version");
        let parts: Vec<&str> = full.split('.').take(2).collect();
        parts.join(".")
    };
    let clients = get("connected_clients");
    let mem = get("used_memory_human");
    let up_days = get("uptime_in_days");

    // Sum keys across all DBs from the `# Keyspace` section
    // (lines like `db0:keys=145,expires=0,avg_ttl=0`).
    let keys: i64 = info
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("db")?;
            let (_, kv) = rest.split_once(':')?;
            let (_, nums) = kv.split_once("keys=")?;
            nums.split(',').next()?.parse::<i64>().ok()
        })
        .sum();

    let line = format!("v{version}  clients {clients}  mem {mem}  keys {keys}  up {up_days}d");
    Ok((mask_password(&url), line))
}

/// Mask the password in a connection URL for safe display.
///
/// `postgres://sentin8:secret@host:5432/db` → `postgres://sentin8@host:5432/db`
/// `valkeys://:secret@host:6379/0`         → `valkey://host:6379/0`
/// URLs without a userinfo/password are returned unchanged.
fn mask_password(url: &str) -> String {
    // Quick check: only scheme://user[:pass]@host... has an '@'.
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = &url[scheme_end + 3..];
    let Some(at) = after_scheme.find('@') else {
        return url.to_string();
    };
    let userinfo = &after_scheme[..at];
    let host_and_rest = &after_scheme[at..]; // includes the leading '@'
    let shown_userinfo = match userinfo.find(':') {
        // Drop everything from the first ':' onward (the password + any
        // trailing userinfo). Keep the username so the line stays readable.
        Some(colon) => &userinfo[..colon],
        None => userinfo,
    };
    format!(
        "{}{}{}",
        &url[..scheme_end + 3],
        shown_userinfo,
        host_and_rest
    )
}
