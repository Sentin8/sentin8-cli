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
//!   PostgreSQL dependency - it must be able to boot and report status even
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
    println!("  Domain      {}", domain_line());
    println!("  ACME        {}", acme_line());
    println!("  TLS PQ mode {}", pq_mode_line());
    // Blank line separates the infra block from the service table that follows.
    println!();
}

/// Build the TLS post-quantum posture line (PQCA-1).
///
/// `SENTIN8_TLS_PQ_MODE` is not a cosmetic knob: it namespaces the CA
/// hierarchy, the acme data dir, the leaf cache AND the negotiated
/// handshake. A CLI process that resolves a different posture than the
/// running fleet fails at the TLS layer with a bare
/// `received fatal alert: HandshakeFailure` - which reads like a trust
/// or routing problem and is neither. Printing it here is what turns that
/// into a one-glance diagnosis.
///
/// The default printed is the same one `sentin8_config::pq_mode()`
/// applies (`exclusive` when unset/unknown), so an UNSET variable is
/// shown as the posture that is actually in force, not as a blank.
fn pq_mode_line() -> String {
    let raw = std::env::var("SENTIN8_TLS_PQ_MODE").unwrap_or_default();
    let mode = sentin8::config::pq_mode();
    let note = match mode.as_str() {
        "classical" => "TLS 1.2/1.3, RSA/ECDSA certificates",
        "hybrid" => "X25519MLKEM768 with a classical fallback",
        "exclusive" => "PQ-only handshakes",
        _ => "",
    };
    if raw.trim().is_empty() {
        format!("{mode}  (UNSET - the compiled default)  [{note}]")
    } else {
        format!("{mode}  [{note}]")
    }
}

/// Build the platform-domain summary line (TLS-EXPOSURE-1).
///
/// Prints the root the fleet derives every hostname from, and flags the
/// two shapes that catch operators out:
///
/// - a MISSING domain - the fleet would fall back to the compiled default
///   while the operator believes something else is configured;
/// - a domain that is not one of the builtin local roots, which means
///   every hostname is publicly resolvable and must be backed by real
///   DNS.
///
/// This is the line that answers "which domain am I actually testing?"
/// without reading `.env` by hand - the failure it prevents is a rig that
/// silently runs against a stale domain left over from an earlier
/// campaign.
fn domain_line() -> String {
    match std::env::var("SENTIN8_DOMAIN") {
        Ok(d) if !d.trim().is_empty() => {
            let d = d.trim().to_string();
            if d.ends_with("local.sentin8.dev") || d == "local.sentin8.dev" {
                format!("{d}  [loopback wildcard]")
            } else {
                format!("{d}  [public DNS required]")
            }
        }
        _ => "UNSET (falls back to the compiled default - set SENTIN8_DOMAIN)".to_string(),
    }
}

/// Build the ACME issuance summary line (TLS-EXPOSURE-1, acme DESIGN §4.1b).
///
/// Shows which CA signs certificates, straight from the env the fleet
/// boots with - no call to acme. Three shapes:
///
/// - `internal only (SENTIN8_ACME_FORCE_INTERNAL=true)` - every order is
///   platform-CA signed; no upstream client exists.
/// - `internal only (no upstream)` - the same outcome, by omission.
/// - `internal + upstream <directory>` - enrolled `external` hostnames
///   relay to that CA; everything else stays internal.
///
/// Production Let's Encrypt is called out explicitly, because a test rig
/// pointed there burns the per-domain weekly quota.
fn acme_line() -> String {
    let force = std::env::var("SENTIN8_ACME_FORCE_INTERNAL")
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);
    if force {
        return "internal only (SENTIN8_ACME_FORCE_INTERNAL=true)".to_string();
    }
    let dir = std::env::var("SENTIN8_ACME_UPSTREAM_DIRECTORY_URL")
        .unwrap_or_default()
        .trim()
        .to_string();
    if dir.is_empty() {
        return "internal only (no upstream configured)".to_string();
    }
    // Strip the scheme so the line stays one row wide.
    let shown = dir
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if shown.contains("acme-v02.api.letsencrypt.org") {
        format!("internal + upstream {shown}  [PRODUCTION LET'S ENCRYPT - use staging for tests]")
    } else if shown.contains("acme-staging") {
        format!("internal + upstream {shown}  [Let's Encrypt STAGING]")
    } else {
        format!("internal + upstream {shown}")
    }
}

/// Reduce a noisy connection error to a single tidy line.
fn short_err(e: &anyhow::Error) -> String {
    let s = e.to_string();
    let first = s.split('\n').next().unwrap_or(&s);
    first.chars().take(90).collect::<String>()
}

/// Build the PostgreSQL summary line.
///
/// Returns `(masked_url, summary)` - e.g.
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
/// Returns `(masked_url, summary)` - e.g.
/// `("valkeys://host:6379/0", "v9.1  clients 23  mem 12.3M  keys 145  up 3d")`.
///
/// Connects over the certificate-identity TLS plane via Valkey GLIDE
/// with the local CONTROL identity (read-only - status probes never
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
            // get an INFO document - surface it as a probe error instead
            // of rendering an empty summary (the silent
            // empty-string fallback made the line look connected-but-blank).
            glide::ValkeyValue::VerbatimString { text, .. } => Ok(text),
            glide::ValkeyValue::BulkString(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
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
