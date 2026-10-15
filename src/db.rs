// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Database lifecycle — `sentin8 db bootstrap`, `sentin8 db migrate`, and
//! `sentin8 db seed-listings`.
//!
//! BOOTSTRAP-1 (architecture-principles §6.5): the database has exactly two
//! states, split by the `sys.platform_bootstrap` scout.
//!
//! - **Not initialized** — the only credential available is the database
//!   username/password (Auth is not up). `db bootstrap` is the ONLY command
//!   that applies SQL; it refuses if the scout already exists.
//! - **Initialized** — every CLI action requires a signed-in operator.
//!   Destructive reset does NOT exist in the platform CLI; local development
//!   uses the repo's `scripts/dev-destroy.sh` (guarded by `SENTIN8_DEV=1`,
//!   never shipped).
//!
//! Connects directly to PostgreSQL via `DATABASE_URL` (from `.env`) using
//! the certificate-identity pool factory (`sentin8::config::pg_pool`, group
//! DESIGN.md §3.2) — the operator presents the `postgres-ops` infra pair,
//! and no database password exists. `db bootstrap` additionally writes the
//! platform roles' identity rows into `pg_ident.conf`. Valkey is flushed
//! via the SyncGlideClient factory using `VALKEY_URL`. Init scripts are
//! embedded at compile time via `include_str!` so the CLI binary is
//! self-contained.
//!
//! `seed-listings` scans all domain `apps/` directories for
//! `app-listing.json` files and upserts them into `sentin8_app_store_listings`.
//! This enables auto-registration: any app with an `app-listing.json`
//! manifest is automatically registered in the app store without manual
//! API calls.

use sqlx::postgres::PgConnection;
use sqlx::Connection;

/// Platform/shared SQL scripts, loaded at runtime from the CLI's
/// `migrations/` directory.
///
/// Only platform-level SQL lives here — RLS helpers, shared tables, OAuth
/// roles. Service-specific SQL (table creation, indexes, RLS policies, seed
/// data) is loaded at runtime from `--sql-dir` paths (typically
/// `services/*/sql/`). This keeps the CLI binary decoupled from any
/// specific service's schema.
///
/// Applied in order by `sentin8 db reset` and `sentin8 db migrate`:
/// platform SQL first, then service SQL from `--sql-dir` paths.
/// Platform SQL: RLS helpers, domain resolver triggers, OAuth roles, grants.
/// Applied as a single file by `sentin8 db reset` before service SQL.
const PLATFORM_SQL: &str = include_str!("migrations/platform.sql");
const PUBLIC_HELPERS_SQL: &str = include_str!("migrations/public_helpers.sql");

/// Scout table (BOOTSTRAP-1): platform-level marker written ONCE by
/// `db bootstrap`. Its existence means "initialized" — every subsequent CLI
/// action requires a signed-in operator, and no destructive command exists.
const BOOTSTRAP_SCOUT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sys.platform_bootstrap (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    bootstrapped_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    operator_note   TEXT NOT NULL DEFAULT '',
    schema_version  TEXT NOT NULL DEFAULT ''
);
"#;

/// Scout check — `true` when the platform is already initialized.
/// Absence of the scout with ANY platform table present is still
/// treated as initialized (a half-finished bootstrap must not open a
/// second window; re-run from scratch via the dev script).
async fn platform_initialized(pool: &sqlx::PgPool) -> anyhow::Result<bool> {
    // The scout table may not exist yet — an error means "not initialized"
    // (undefined_table), anything else is a real failure.
    // (i64: `SELECT 1` yields INT4; an i16 decode mismatch made bootstrap
    // refuse on an initialized platform.)
    let scout = sqlx::query_as::<_, (i32,)>(r#"SELECT 1 FROM sys.platform_bootstrap WHERE id = 1"#)
        .fetch_optional(pool)
        .await;
    match scout {
        Ok(Some(_)) => return Ok(true),
        Ok(None) => return Ok(true), // table exists, row absent → initialized
        Err(sqlx::Error::Database(db)) if db.message().contains("does not exist") => {
            // scout table missing — fall through to the table-presence check
        }
        Err(e) => return Err(anyhow::anyhow!("scout check failed: {e}")),
    }
    // Half-initialized guard: platform SQL applied but scout not written.
    let table_count: Option<i64> = sqlx::query_scalar(
        r#"SELECT count(*) FROM information_schema.tables
             WHERE table_schema = 'sys'"#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(Some(0));
    Ok(table_count.unwrap_or(0) > 0)
}

/// The platform roles' certificate-identity rows (group DESIGN.md §3.2).
///
/// Each `sentin8_{service}_service` role binds to its workload's
/// `m2m-{workload}` CN. The CN MUST be the certificate SUBJECT — the
/// m2m mint names workloads by the service_type colon identity
/// (`m2m-sentin8:auth`), which `make infra-tls` pre-mints as
/// `sentin8_auth.crt`. The two legacy shared dev roles bind to the app
/// workload; the DDL superuser row (`m2m-postgres-ops` → `sentin8`) lives
/// in the `make infra-tls` seed, not here.
pub fn platform_pg_ident_rows() -> Vec<(String, String)> {
    // The OPERATOR row first — `make infra-tls` seeds it, and the CLI's
    // convergence write re-adds it after ANY file reset (manual churn or
    // a lost file): without it, `db bootstrap`/enroll/ops tooling cannot
    // connect AT ALL (the DDL role has no password to fall back to).
    let mut rows: Vec<(String, String)> =
        vec![("m2m-postgres-ops".to_string(), "sentin8".to_string())];
    let services = [
        "auth", "sys", "stat", "cron", "flow", "func", "db", "storage", "tls", "app", "post",
        "bus", "bff", "secrets", "ai", "captain", "proxy", "acme", "web",
    ];
    rows.extend(
        services
            .iter()
            .map(|s| (format!("m2m-sentin8:{s}"), format!("sentin8_{s}_service")))
            .collect::<Vec<(String, String)>>(),
    );
    // Legacy shared dev roles (sentin8-config default_database_url) —
    // same app workload identity.
    rows.push(("m2m-sentin8:app".to_string(), "sentin8_app".to_string()));
    rows.push(("m2m-sentin8:app".to_string(), "sentin8_app_dev".to_string()));
    rows
}

/// Append `(cn, role)` rows to the PostgreSQL identity map
/// (`{SENTIN8_SECRETS_DIR}/infra-tls/pg_ident.conf`) — the certificate-
/// identity counterpart of the role-creation pass (group DESIGN.md
/// §3.2). Rows are appended as plain `pgm` map lines; PostgreSQL
/// re-reads the file per connection, so no server restart is needed.
/// Idempotent: a row already present is skipped, so re-running
/// bootstrap/enroll converges without duplicates.
pub async fn write_pg_ident_rows(rows: &[(String, String)]) -> anyhow::Result<()> {
    let secrets =
        std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".to_string());
    let path = std::path::Path::new(&secrets).join("infra-tls/pg_ident.conf");
    let existing = std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!("read {}: {e} (run `make infra-tls` first)", path.display())
    })?;
    let mut additions = String::new();
    for (cn, role) in rows {
        let line = format!("pgm        {cn:<22} {role}\n");
        if !existing.lines().any(|l| {
            let mut parts = l.split_whitespace();
            parts.next() == Some("pgm")
                && parts.next() == Some(cn.as_str())
                && parts.next() == Some(role.as_str())
        }) {
            additions.push_str(&line);
        }
    }
    if additions.is_empty() {
        return Ok(());
    }
    let mut content = existing;
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&additions);
    std::fs::write(&path, content).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    println!(
        "  pg_ident.conf: {} role↔identity row(s) written (certificate identity, §3.2)",
        rows.len()
    );
    // THE RELOAD IS NOT OPTIONAL: pg_ident.conf (like pg_hba.conf) is
    // parsed only at startup and on SIGHUP — never per connection. A row
    // written but not reloaded is dead weight: the connection that binds
    // the freshly enrolled workload's CN would fail `no match in usermap`
    // until someone reloads by hand. The reload rides the OPERATOR's
    // identity (the ops pair — present from `make infra-tls` and always
    // in the map after the convergence write above); pg_reload_conf
    // returns immediately, the new rows are armed for everyone by the
    // time this function returns.
    let ops_dsn = std::env::var("SENTIN8_OPS_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/postgres".to_string());
    match sentin8::config::pg_pool::connect(&ops_dsn).await {
        Ok(ops_pool) => {
            let reloaded: Result<bool, _> = sqlx::query_scalar("SELECT pg_reload_conf()")
                .fetch_one(&ops_pool)
                .await;
            match reloaded {
                Ok(true) => println!("  pg_ident.conf: server reload armed (pg_reload_conf)"),
                Ok(_) => println!("  WARNING: pg_reload_conf returned false — new identity rows stay unarmed until a manual SIGHUP"),
                Err(e) => println!(
                    "  WARNING: could not arm the identity rows ({}:5432): {} — new rows require a manual SIGHUP",
                    ops_dsn.split('@').next_back().unwrap_or("?"), e
                ),
            }
        }
        Err(e) => println!(
            "  WARNING: ops pool connect failed — new identity rows require a manual SIGHUP: {e}"
        ),
    }
    Ok(())
}

/// `sentin8 db bootstrap` — one-time platform initialization.
///
/// Preconditions: the `sys.platform_bootstrap` scout does NOT
/// exist and no platform tables are present. The only credential
/// needed is the operator's certificate identity (`postgres-ops`,
/// mapped to the DDL superuser — group DESIGN.md §3.2; Auth does not
/// exist yet).
///
/// Steps (see architecture-principles §6.5 + CLI design §5.12):
/// 1. Scout check — refuse when initialized.
/// 2. Drop-safe schema creation: CREATE SCHEMA IF NOT EXISTS (no DROP —
///    the refusal in step 1 is the destructive gate).
/// 3. Apply platform SQL (RLS helpers, roles, grants) + service SQL via
///    the self-describing path (roles BEFORE SQL, incident 2026-08-28)
///    and write the platform roles' certificate-identity rows.
/// 4. The bootstrap admin keeps its SQL-seed credential `a@m.n` / `pass` —
///    the platform never rotates it (BOOTSTRAP-2.2, CLI design §5.12).
/// 5. Write the scout (same transaction as the password update).
pub async fn bootstrap(operator_note: Option<&str>) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let repo_root = std::env::current_dir()?;

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;

    // 1. Scout gate — the destructive-line refusal.
    if platform_initialized(&pool).await? {
        anyhow::bail!(
            "platform already initialized — refusing to bootstrap again.\n\
             Destructive reset does not exist in the platform CLI; for local \
             development use scripts/dev-destroy.sh (requires SENTIN8_DEV=1)."
        );
    }
    println!("Platform not initialized — bootstrapping ...");

    // 2. Ensure schemas exist (create-if-missing only; NO drops). DBX: the
    //    platform database owns ONE SCHEMA PER SERVICE (architecture-
    //    principles §6.6); vertical schemas no longer exist here — each
    //    vertical gets its own DATABASE via `sentin8-cli vertical init`.
    println!("Creating schemas ...");
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS public; \
         CREATE SCHEMA IF NOT EXISTS auth; \
         CREATE SCHEMA IF NOT EXISTS sys; \
         CREATE SCHEMA IF NOT EXISTS bus; \
         CREATE SCHEMA IF NOT EXISTS post; \
         CREATE SCHEMA IF NOT EXISTS stat; \
         CREATE SCHEMA IF NOT EXISTS db; \
         CREATE SCHEMA IF NOT EXISTS flow; \
         CREATE SCHEMA IF NOT EXISTS func; \
         CREATE SCHEMA IF NOT EXISTS cron; \
         CREATE SCHEMA IF NOT EXISTS app; \
         CREATE SCHEMA IF NOT EXISTS bff; \
         CREATE SCHEMA IF NOT EXISTS secrets; \
         CREATE SCHEMA IF NOT EXISTS storage; \
         CREATE SCHEMA IF NOT EXISTS ai; \
         CREATE SCHEMA IF NOT EXISTS tls; \
         CREATE SCHEMA IF NOT EXISTS proxy; \
         GRANT ALL ON SCHEMA public TO public;",
    )
    .execute(&pool)
    .await?;

    // 3. Platform SQL (RLS helpers, roles, grants) + the platform roles'
    // certificate-identity rows (group DESIGN.md §3.2).
    println!("Applying platform SQL ...");
    sqlx::raw_sql(PLATFORM_SQL).execute(&pool).await?;
    // DBX (§6.7) — the outbox relay helper must exist in db sentin8 too:
    // the `sentin8` vertical skips the vertical-DB apply (its database
    // pre-exists), so bootstrap is the only authoritative apply point here.
    sqlx::raw_sql(PUBLIC_HELPERS_SQL).execute(&pool).await?;
    // PostgreSQL certificate identity (§3.2): bind every platform role to
    // its workload CN in the identity map. The `m2m-{workload}` names are
    // the binary-name identities the m2m mint loop uses (`sentin8-auth`,
    // …); the operator row is in the seed (`m2m-postgres-ops` → `sentin8`).
    write_pg_ident_rows(&platform_pg_ident_rows()).await?;

    // 4. Flush Valkey (stale registrations from a prior platform life).
    flush_valkey();

    // 5. Scout — written here so a half-platform still refuses a second
    //    bootstrap (platform_initialized also checks table presence). The
    //    bootstrap-admin credential is never rotated by the platform
    //    (BOOTSTRAP-2.2): `vertical enroll` applies auth's seed user
    //    a@m.n/pass as-is and `db finalize` only marks the window closed.
    sqlx::raw_sql(BOOTSTRAP_SCOUT_SQL).execute(&pool).await?;
    sqlx::query(
        r#"INSERT INTO sys.platform_bootstrap
               (id, operator_note, schema_version)
             VALUES (1, $1, $2)
             ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(operator_note.unwrap_or(""))
    .bind(env!("CARGO_PKG_VERSION"))
    .execute(&pool)
    .await?;

    println!();
    println!("Bootstrap complete (schema + scout written).");
    println!("Next: `vertical enroll <registry>` applies service SQL, then");
    println!("`db finalize` marks the bootstrap window closed (credential-free).");
    println!("Local one-shot: scripts/dev-destroy.sh runs all four steps.");

    let _ = repo_root;
    Ok(())
}

/// `sentin8 db finalize` — post-enroll lifecycle marker (BOOTSTRAP-1).
///
/// The bootstrap sequence is: `db bootstrap` (schema + scout, DB
/// credentials only) → `vertical enroll` (service SQL) → `db finalize`
/// (mark the scout finalized) → `captain start`.
///
/// BOOTSTRAP-2.2 (2026-09-09 revision): finalize does NOT touch the
/// bootstrap-admin credential — the SQL-seed `a@m.n` / `pass` stays valid
/// through bootstrap and forever after, until the operator changes it via
/// self-service (Dash → Security). Finalize only writes `finalized_at` so
/// operators and tooling can tell the enroll window is closed. Idempotent:
/// a second run is a no-op success, not an error.
pub async fn finalize() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;

    // Scout must exist — finalize is a post-bootstrap step.
    let scout: Option<(i32,)> =
        sqlx::query_as(r#"SELECT 1 FROM sys.platform_bootstrap WHERE id = 1"#)
            .fetch_optional(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("scout check failed (run `db bootstrap` first): {e}"))?;
    if scout.is_none() {
        anyhow::bail!("platform is not bootstrapped — run `sentin8-cli db bootstrap` first");
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"ALTER TABLE sys.platform_bootstrap
             ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ"#,
    )
    .execute(&mut *tx)
    .await?;
    let already: (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as(r#"SELECT finalized_at FROM sys.platform_bootstrap WHERE id = 1"#)
            .fetch_one(&mut *tx)
            .await?;
    if already.0.is_none() {
        sqlx::query(
            r#"UPDATE sys.platform_bootstrap
                  SET finalized_at = now() WHERE id = 1"#,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        println!();
        println!("Bootstrap finalized (bootstrap window closed).");
        println!("  Bootstrap admin: a@m.n — password unchanged (SQL seed `pass`).");
        println!("  Change it whenever you like via the self-service flow.");
    } else {
        tx.rollback().await?;
        println!("Bootstrap already finalized — nothing to do.");
    }
    Ok(())
}

/// `sentin8 db migrate` — re-apply platform SQL without dropping (operator
/// recovery on an already-initialized platform; adds nothing, destroys
/// nothing). Vertical SQL is not accepted here — verticals self-describe
/// via `vertical enroll`.
pub async fn migrate(_sql_dirs: &Option<String>) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // Apply platform SQL (RLS helpers, domain triggers, OAuth roles, grants).
    println!("Applying platform SQL ...");
    {
        let mut conn = connect().await?;
        sqlx::raw_sql(PLATFORM_SQL).execute(&mut conn).await?;
    }

    println!("Platform SQL applied.");
    Ok(())
}

/// `sentin8 db seed-listings` — auto-register apps from app-listing.json
/// manifests.
///
/// Scans `sentin8/apps/` (plus any extra dirs passed via `--apps-dir`) for
/// `app-listing.json` files and upserts each into the `sentin8_app_store_listings` table. The system org
/// (`00000000-…-0001`) and system env (`…-0002`) are used as the owner,
/// with `visibility='public'` and `status='published'` so all orgs can
/// see and install the apps.
pub async fn seed_listings(apps_dirs: &Option<String>) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let repo_root = std::env::current_dir()?;

    // Discover all app-listing.json files under apps/ directories.
    // Always scan sentin8/apps. If apps_dirs is provided, scan those too.
    let mut domain_dirs = vec!["sentin8/apps".to_string()];
    if let Some(extra) = apps_dirs {
        domain_dirs.extend(extra.split(',').map(|s| s.trim().to_string()));
    }
    let mut listings: Vec<(String, serde_json::Value)> = Vec::new(); // (path, json)

    for domain_dir in &domain_dirs {
        let apps_dir = repo_root.join(domain_dir);
        if !apps_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&apps_dir)? {
            let entry = entry?;
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let listing_path = entry.path().join("app-listing.json");
            if !listing_path.is_file() {
                continue;
            }
            let slug = entry.file_name().to_string_lossy().to_string();
            let contents = std::fs::read_to_string(&listing_path)?;
            // Strip the "//" comment field if present (JSON5-style).
            let cleaned = strip_json_comment(&contents);
            let json: serde_json::Value = serde_json::from_str(&cleaned)
                .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", listing_path.display()))?;
            println!("  found listing: {domain_dir}/{slug}/app-listing.json");
            listings.push((slug, json));
        }
    }

    if listings.is_empty() {
        println!("No app-listing.json files found. Nothing to seed.");
        return Ok(());
    }

    println!("Seeding {} app listing(s) ...", listings.len());

    // System org/env UUIDs — the platform owner for auto-registered apps.
    let sys_org_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);
    let sys_env_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);
    let system_user_sub = "system";

    let mut conn = connect().await?;

    // Ensure the app.store_listings table exists before seeding.
    // This table is normally created by app on startup, but
    // seed_listings may run before app has started (e.g. during
    // `db reset`). Create a minimal version here so the upsert works.
    // When app starts, its init_db will add any missing columns.
    sqlx::raw_sql(
        r#"CREATE TABLE IF NOT EXISTS app.store_listings (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            app_name        TEXT NOT NULL,
            app_slug        TEXT NOT NULL UNIQUE,
            description     TEXT,
            backend_url     TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'disabled')),
            supports_dcr    BOOLEAN NOT NULL DEFAULT false,
            oauth_defaults  JSONB NOT NULL DEFAULT '{}',
            created_by      TEXT NOT NULL DEFAULT '',
            usr_id          TEXT NOT NULL DEFAULT '',
            visibility      TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('usr', 'env', 'org', 'public')),
            org_id          UUID,
            env_id          UUID,
            roles           JSONB NOT NULL DEFAULT '[]',
            default_signup_role TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );"#,
    )
    .execute(&mut conn)
    .await?;

    for (slug, json) in &listings {
        let app_name = json
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or(slug.as_str());
        let app_slug = json
            .get("app_slug")
            .and_then(|v| v.as_str())
            .unwrap_or(slug.as_str());
        let description = json.get("description").and_then(|v| v.as_str());
        let backend_url = json
            .get("backend_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let supports_dcr = json
            .get("supports_dcr")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let visibility = json
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("public");
        let status = json
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("published");
        let oauth_defaults = json
            .get("oauth_defaults")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let roles = json.get("roles").cloned().unwrap_or(serde_json::json!([]));
        let default_signup_role = json.get("default_signup_role").and_then(|v| v.as_str());

        // Upsert by (app_slug, channel) — APP-4: a listing row is a
        // (slug, channel) release; the manifest may pin `version` and
        // `channel` (defaults 0.0.0 / stable).
        let version = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let channel = json
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("stable");
        let rows = sqlx::query(
            r#"INSERT INTO app.store_listings
                  (app_name, app_slug, description, backend_url, supports_dcr,
                   oauth_defaults, created_by, usr_id, visibility, org_id, env_id,
                   status, roles, default_signup_role, version, channel)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14, $15)
               ON CONFLICT (app_slug, channel) DO UPDATE SET
                   app_name = EXCLUDED.app_name,
                   description = EXCLUDED.description,
                   backend_url = EXCLUDED.backend_url,
                   supports_dcr = EXCLUDED.supports_dcr,
                   oauth_defaults = EXCLUDED.oauth_defaults,
                   visibility = EXCLUDED.visibility,
                   status = EXCLUDED.status,
                   roles = EXCLUDED.roles,
                   default_signup_role = EXCLUDED.default_signup_role,
                   version = EXCLUDED.version,
                   updated_at = now()
               RETURNING id"#,
        )
        .bind(app_name)
        .bind(app_slug)
        .bind(description)
        .bind(backend_url)
        .bind(supports_dcr)
        .bind(&oauth_defaults)
        .bind(system_user_sub)
        .bind(visibility)
        .bind(sys_org_id)
        .bind(sys_env_id)
        .bind(status)
        .bind(&roles)
        .bind(default_signup_role)
        .bind(version)
        .bind(channel)
        .fetch_all(&mut conn)
        .await
        .map_err(|e| anyhow::anyhow!("failed to upsert listing for '{app_slug}': {e}"))?;

        let action = if !rows.is_empty() {
            "seeded"
        } else {
            "updated"
        };
        println!("  {action}: {app_slug} ({app_name})");
    }

    println!("App listings seeded.");
    Ok(())
}

/// Strip a top-level `"//"` key from a JSON string — the app-listing.json
/// files contain a `"//"` comment field that is valid JSON but semantically
/// a comment. We remove it to avoid storing it.
fn strip_json_comment(raw: &str) -> String {
    // Simple approach: parse as Value, remove the "//" key, re-serialize.
    // If parsing fails even with the key, the caller will report the error.
    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(obj) = val.as_object_mut() {
            obj.remove("//");
        }
        return serde_json::to_string_pretty(&val).unwrap_or_else(|_| raw.to_string());
    }
    raw.to_string()
}

// ── helpers ─────────────────────────────────────────────────────────────

/// Connect to PostgreSQL using `DATABASE_URL` from the environment —
/// over the certificate-identity TLS plane (the operator presents the
/// `postgres-ops` pair; group DESIGN.md §3.2).
async fn connect() -> anyhow::Result<PgConnection> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let opts = sentin8::config::pg_pool::connect_options_for(&url)?;
    Ok(PgConnection::connect_with(&opts).await?)
}

/// Best-effort Valkey FLUSHALL — degrades silently if Valkey is unreachable.
/// Presents the operator's admin identity via the SDK's sync GLIDE
/// factory (the control path owns resets; group DESIGN.md §3.1).
fn flush_valkey() {
    let url = std::env::var("VALKEY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(sentin8::config::service_valkey_url);
    println!("Flushing Valkey ...");
    let result = std::thread::spawn(move || -> anyhow::Result<()> {
        let client = sentin8::middleware::valkey_client_sync(&url, "valkey-admin")?;
        client
            .custom_command(&["FLUSHALL"])
            .map_err(|e| anyhow::anyhow!("FLUSHALL: {e}"))?;
        Ok(())
    })
    .join();
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("  warning: Valkey flush failed: {e}"),
        Err(_) => eprintln!("  warning: Valkey flush thread panicked"),
    }
}
