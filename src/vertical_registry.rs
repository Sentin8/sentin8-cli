// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Vertical registry — `sentin8-cli vertical enroll/unenroll`.
//!
//! Enrolls a vertical domain (bank8, hotel8, etc.) with the platform.
//! Reads a `vertical-registry.json` file and:
//!   1. Writes service domain mappings to `sentin8_domains` (for sys).
//!   2. Writes cross-service endpoint URLs to Valkey (for captain to propagate
//!      as env vars to services that need to call vertical services).
//!   3. Registers known event verticals in Valkey (for bff).
//!   4. Registers service definitions in `sentin8_vertical_services` (for
//!      sys domain mapping derivation).
//!   5. Registers consent data providers in `sentin8_consent_providers` (for
//!      auth to call vertical services during consent flows).
//!   6. Registers error codes in a `sentin8_vertical_error_codes` table.
//!   7. Registers audit findings in a `sentin8_vertical_audit_findings` table.
//!
//! This keeps sentin8 decoupled from verticals at compile time — all
//! domain knowledge is provided at runtime via the registry file.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// GLIDE's `custom_command` (raw RESP, the ACL-provisioning surface) is a
// trait method — bring it into scope for the async GlideClient calls.
use glide::CustomCommand as _;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerticalRegistry {
    pub vertical: String,
    #[serde(default)]
    pub verticals: Vec<String>,
    pub services: Vec<RegistryService>,
    /// Vertical-wide env vars (REG-9 / design `sentin8-service-self-registration-design.md`
    /// §3.5): merged into EVERY service's captain catalog `extra_env` at
    /// enroll/add-catalog time, with the per-service `services[].extra_env`
    /// value winning on key conflict. Lets a vertical set env vars as a whole
    /// (region, log format, feature flags) without repeating them per service.
    /// captain only ever sees the merged flat map — precedence inside captain
    /// is unchanged (platform-propagated vars still win over catalog values).
    #[serde(default)]
    pub extra_env: std::collections::HashMap<String, String>,
    /// Directory containing app folders with `app.json` files (SELFREG-10).
    /// Defaults to `"apps"` (i.e. `{vertical_root}/apps/*/app.json`).
    /// Can be overridden for non-standard layouts.
    #[serde(default = "default_apps_dir")]
    pub apps_dir: String,
    /// Vertical-wide default Shield policy sets (Phase 28). Applied to the
    /// named `service` in each entry (unlike per-service `services[].policies`,
    /// which inherits the service_type). Same table/upsert path as per-service
    /// policy sets.
    #[serde(default)]
    pub policies: Vec<RegistryPolicySet>,
    /// Vertical-wide default ReBAC relation tuples (Phase 28 §3.1c). Applied
    /// to the named `service` in each entry; same table/upsert path as
    /// per-service relations.
    #[serde(default)]
    pub relations: Vec<RegistryRelation>,
    /// Apps hosted by this vertical (Flutter web apps). Each entry has a
    /// `slug` and a `path` to the app's `app.json` file (relative to the
    /// vertical root). The CLI reads each `app.json` for listing metadata.
    #[serde(default)]
    pub apps: Vec<RegistryApp>,
    #[serde(default)]
    pub consent_providers: Vec<ConsentProvider>,
    #[serde(default)]
    pub service_actions: Vec<ServiceAction>,
    #[serde(default)]
    pub error_codes: Vec<RegistryErrorCode>,
    #[serde(default)]
    pub audit_findings: Vec<RegistryAuditFinding>,
    /// SQL directories to apply during `vertical init` (e.g.
    /// `["services/ledger/sql", "services/payments/sql"]`).
    /// Each directory is scanned for `*.sql` files at runtime.
    #[serde(default)]
    pub sql_dirs: Vec<String>,
    /// Admin UI entries for this vertical's services. Each entry declares the
    /// service's admin pages (label, icon, service_flag, pages) that
    /// Sentin8:Dash discovers at runtime to build its dynamic sidebar.
    /// See `sentin8-architecture-principles.md` §4.15.
    #[serde(default)]
    pub admin_ui: Vec<serde_json::Value>,
    /// Consent flows declared by this vertical. Each flow defines a trigger
    /// pattern (glob), the vertical service that owns the consent UI, and
    /// the endpoints for the consent RFW (ui/approve/deny). Registered
    /// during `vertical enroll` into `sentin8_consent_flows`. See
    /// `sentin8-architecture-principles.md` §4.16.
    #[serde(default)]
    pub consent_flows: Vec<ConsentFlow>,
    /// CLI commands declared by this vertical's services (design §9.1).
    /// Stored in `sentin8_cli_commands` during `vertical enroll` and
    /// dynamically exposed by the CLI's generic executor — no hardcoded
    /// service subcommands. See `sentin8-sentin8-cli-technical-design.md` §9.
    #[serde(default)]
    pub cli_commands: Vec<CliCommand>,
    /// Declarative Valkey ACL for this vertical's MemBus (fast data
    /// plane) namespaces. When present, `vertical enroll` creates the
    /// ACL user with the declared key patterns and command allowlist —
    /// mirroring how it creates PostgreSQL roles and OAuth scopes.
    /// The secret is stored by reference (never in tables) and injected
    /// into services via `MEMBUS_VALKEY_ACL_SECRET`. See
    /// `sentin8-membus-technical-design.md` §7.2.
    #[serde(default)]
    pub valkey: Option<RegistryValkeyAcl>,
}

/// Declarative Valkey ACL (`vertical-registry.json` `valkey` section).
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryValkeyAcl {
    /// ACL user name (per vertical, e.g. `exchange8`).
    pub acl_user: String,
    /// Key patterns the vertical may touch (`~` patterns): its MemBus
    /// namespaces and control-plane bus streams.
    pub key_patterns: Vec<String>,
    /// RESP commands the vertical may issue.
    pub commands: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryService {
    pub service_type: String,
    /// Executable name for `--print-registration` + captain catalog spawn.
    /// Defaults to `service_type` (REG-7: binary == service_type in 47/47
    /// services platform-wide — set only as an override, e.g. a `-worker`
    /// suffix split or an explicit path). The CLI resolves it via
    /// `resolve_binary_path` (SENTIN8_CAPTAIN_BINARY_PREFIX dirs →
    /// `{vertical}/target/release/` → `{vertical}/`).
    #[serde(default = "default_binary_from_service_type")]
    pub binary: String,
    /// Subdomain label for this service's hostname (e.g. `func` for
    /// `func.ops.sys.sentin8.local`). Defaults to `service_type`
    /// (REG-7: trivial mapping in all verticals — the sentin8 platform
    /// registry overrides it to short labels `auth`/`db`/`sys`, which are
    /// the ONLY legitimate overrides). The binary's
    /// `--print-registration --section=service` also emits it; a
    /// registry value takes precedence.
    #[serde(default = "default_subdomain_from_service_type")]
    pub subdomain: String,
    #[serde(default)]
    pub health_path: Option<String>,
    /// Captain start priority tier (lower starts first).
    #[serde(default = "default_start_priority_reg")]
    pub start_priority: i16,
    /// When true, health probes use plain HTTP instead of HTTPS.
    /// `None` = not declared in the registry JSON — the captain catalog's
    /// own default (per-service: proxy/tls probe their mgmt API over HTTP)
    /// must WIN, so enroll omits the field from the merge entry instead of
    /// overwriting it with a `false` default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_http_health: Option<bool>,
    /// Fixed shell port (None = auto pool). Copied into the captain catalog
    /// entry at enroll so fixed-port services spawn right.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_port: Option<u16>,
    /// Health-check port offset (proxy/tls probe their management API on
    /// `local_port + health_port`). Copied into the captain catalog entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_port: Option<u16>,
    /// Stop-first upgrade: the service owns fixed secondary ports and a
    /// rolling swap would collide (fixed-port listeners).
    #[serde(default)]
    pub upgrade_stop_first: bool,
    /// Extra env vars injected into the spawned process (well-known port
    /// map, feature flags).
    #[serde(default)]
    pub extra_env: std::collections::HashMap<String, String>,
    /// Default Shield policy sets declared for this service (Phase 28,
    /// design/sentin8-policy-technical-design.md §3.2). Upserted into
    /// `policy_sets` by `vertical init`/`enroll` (POLICY-CLI-2);
    /// `origin='platform'` — tenant-authored rows are never touched.
    #[serde(default)]
    pub policies: Vec<RegistryPolicySet>,
    /// Default ReBAC relation tuples declared for this service (§3.1c).
    /// Upserted into `policy_relations` by `vertical init`/`enroll`;
    /// `origin='platform'` — tenant-authored tuples are never touched.
    #[serde(default)]
    pub relations: Vec<RegistryRelation>,
}

/// One declarative Shield policy set in `vertical-registry.json`
/// (design §3.2). For per-service entries (`services[].policies`) the owning
/// `service` is derived from the containing service's `service_type`; for
/// vertical-wide entries (`policies`) the entry carries an explicit
/// `service` (colon service_type). The CLI validates the Shield text at
/// enroll time (POLICY-CLI-1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPolicySet {
    /// Owning service (colon service_type) — REQUIRED for vertical-wide
    /// entries; ignored/overridden for per-service entries.
    #[serde(default)]
    pub service: String,
    pub policy_set_name: String,
    #[serde(default)]
    pub description: String,
    /// Shield policy text — one policy per statement.
    pub policies: String,
    /// Optional Shield schema (Shield policy-schema format).
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default = "default_policy_enabled")]
    pub default_enabled: bool,
    /// Declared posture (`enforced`|`shadow`) — honored verbatim like the
    /// registration path (decision 2026-09-07: no hardcoded shadow).
    #[serde(default = "default_policy_mode")]
    pub mode: String,
}

fn default_policy_enabled() -> bool {
    true
}

fn default_policy_mode() -> String {
    "enforced".to_string()
}

/// One ReBAC relation tuple in `vertical-registry.json` (design §3.1c/§3.2).
/// For per-service entries (`services[].relations`) the owning `service` is
/// derived from the containing service's `service_type`; for vertical-wide
/// entries (`relations`) the entry carries an explicit `service`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRelation {
    /// Owning service (colon service_type) — REQUIRED for vertical-wide
    /// entries; ignored/overridden for per-service entries.
    #[serde(default)]
    pub service: String,
    /// Subject entity type (colon Shield entity type, e.g. `user` | `group`).
    pub subject_type: String,
    pub subject_id: String,
    /// Relation name, e.g. `owner` | `member` | `parent` | `viewer`.
    pub relation: String,
    /// Object entity type (colon Shield entity type, e.g. `account` | `folder`).
    pub object_type: String,
    pub object_id: String,
}

fn default_start_priority_reg() -> i16 {
    40
}

/// REG-7: `binary` defaults to `service_type` — a service's executable is
/// named after the service unless explicitly overridden.
fn default_binary_from_service_type() -> String {
    // Placeholder replaced at deserialize-time via serde's `default` fn
    // signature limitation — see `RegistryService::resolved_binary` usage:
    // serde cannot reference sibling fields in a default fn, so we instead
    // normalize in `load_registry` (empty string means "unset" → service_type).
    String::new()
}

/// REG-7: `subdomain` defaults to `service_type` (normalized in
/// `load_registry` — empty string means "unset").
fn default_subdomain_from_service_type() -> String {
    String::new()
}

/// One app in a registration fragment.
///
/// TWO forms (WARN-11, one file per app repo):
/// - **Inline** (target state): `slug` + `web_dir` + `listing` declared
///   DIRECTLY in the fragment — `service_registration.json` is the app's
///   single self-description; `path` stays unset.
/// - **Pointer** (legacy): `slug` + `path` to an external `app.json`.
///   Resolution prefers inline when `path` is empty/absent.
///
/// The listing shape mirrors what the app-store surface stores
/// (`app_name`, `app_slug`, scopes in `oauth_defaults`, …) — identical
/// for both forms; only the transport differs.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryApp {
    /// App slug (e.g. `ebank`, `dash`).
    pub slug: String,
    /// LEGACY: path to the app's `app.json` file, relative to the vertical
    /// root. Empty/absent → the inline form (web_dir + listing below).
    #[serde(default)]
    pub path: String,
    /// INLINE: the app's web root, relative to the app repo root
    /// (`build/web` for Flutter builds). Inline form only.
    #[serde(default)]
    pub web_dir: String,
    /// INLINE: the app-store listing object (app_name, app_slug,
    /// description, backend_url, oauth_defaults, visibility, status, …).
    #[serde(default)]
    pub listing: serde_json::Value,
    /// The absolute dir of the REPO whose fragment declared this app —
    /// stamped by the loader (NOT authored in JSON). The inline web-root
    /// join needs it: composable enrollment merges fragments into a
    /// temp file, so the merged registry's parent is meaningless.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_dir: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsentProvider {
    pub feature: String,
    pub data_type: String,
    pub service_type: String,
    pub platform_domain_key: String,
    pub endpoint: String,
    pub scope: String,
    pub response_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAction {
    pub action: String,
    pub service_type: String,
    pub platform_domain_key: String,
    pub method: String,
    pub endpoint: String,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryErrorCode {
    pub r#enum: String,
    pub code: String,
    pub status_code: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryAuditFinding {
    pub finding: String,
    pub recommendation: String,
}

/// A consent flow declared by a vertical (§4.16.2). When Sentin8:Auth's
/// `/oauth/authorize` detects that requested scopes match a consent flow's
/// `trigger_patterns`, it redirects to auth-ui's consent page, which
/// fetches the RFW consent definition from the vertical service.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsentFlow {
    /// Unique flow ID (e.g. "fdx_data_sharing").
    pub id: String,
    /// Glob patterns that trigger this consent flow (e.g. ["fdx:recipient:*"]).
    pub trigger_patterns: Vec<String>,
    /// The vertical service type that owns the consent UI (e.g. "bank8-fdx").
    pub service_type: String,
    /// Endpoint on the vertical service that returns the RFW consent page
    /// definition (e.g. "/v1/auth/consent/ui").
    pub ui_endpoint: String,
    /// Endpoint that processes consent approval (e.g. "/v1/auth/consent/approve").
    pub approve_endpoint: String,
    /// Endpoint that records consent denial (e.g. "/v1/auth/consent/deny").
    pub deny_endpoint: String,
}

/// A CLI command declared by a service (design §9.1). The CLI ships a generic
/// executor that reads these from `sentin8_cli_commands` and dynamically
/// exposes them — no hardcoded service subcommands in the CLI binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCommand {
    /// Top-level verb group (e.g. `auth`, `sys`, `ledger`, `pms`).
    pub command: String,
    /// Resource noun (e.g. `user`, `org`, `account`).
    pub subcommand: String,
    /// Verb (e.g. `list`, `create`, `get`, `update`, `delete`).
    pub action: String,
    /// HTTP method (`GET`/`POST`/`PUT`/`DELETE`/`PATCH`).
    pub method: String,
    /// Endpoint path, with `{arg}` placeholders for path args.
    pub path: String,
    /// OAuth scope required (checked against the delegated token before dispatch).
    pub scope: String,
    /// Declared parameters.
    #[serde(default)]
    pub args: Vec<CliCommandArg>,
}

/// A single argument for a CLI command (design §9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCommandArg {
    /// Argument name (e.g. `id`, `email`).
    pub name: String,
    /// Kind: `path`, `query`, `field`, `flag`.
    #[serde(default)]
    pub kind: String,
    /// Whether the argument is required.
    #[serde(default)]
    pub required: bool,
    /// Whether the argument is a secret (masked in --help/history).
    #[serde(default)]
    pub secret: bool,
    /// For `path` args: the placeholder it binds to (e.g. `users/{id}`).
    #[serde(default)]
    pub position: Option<String>,
}

/// An app hosted by a vertical domain (Flutter web app). Registered during
/// `vertical enroll` — the listing metadata is upserted into
/// `sentin8_app_store_listings` and the app directory is registered in
/// Valkey so web knows where to find the built web files.
///
/// Default apps directory name.
fn default_apps_dir() -> String {
    "apps".to_string()
}

/// Load a vertical registry from a JSON file.
pub fn load_registry(path: &str) -> anyhow::Result<VerticalRegistry> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read registry file {path}: {e}"))?;
    let mut registry: VerticalRegistry = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("failed to parse registry file {path}: {e}"))?;
    // REG-7: `binary`/`subdomain` default to `service_type`. The serde
    // default fns emit an empty string (they cannot see sibling fields);
    // normalize here so the rest of the code sees a resolved value and
    // treats empty as "unset" (legacy fallback / subdomain override check).
    // `binary` defaults to the service_type as-is (binaries are named after
    // the dash form of the identity — set explicitly in registries that use
    // colon identities). `subdomain` defaults to the DNS-safe dash form of
    // the identity (architecture-principles.md §6.0) — a colon identity
    // must never leak into a hostname label.
    for svc in &mut registry.services {
        if svc.binary.is_empty() {
            svc.binary = sentin8::config::service_dash_form(&svc.service_type);
        }
        if svc.subdomain.is_empty() {
            svc.subdomain = sentin8::config::service_dash_form(&svc.service_type);
        }
    }
    Ok(registry)
}

/// Initialize a vertical's database schema.
///
/// Binary-sourced (design §5.18): for each service with a `binary` field,
/// runs `--print-registration --section=pg_roles` to create the service's
/// PostgreSQL roles BEFORE any SQL (the 2026-08-28 grant-before-role
/// incident rule), then `--section=sql` and applies pending migrations via
/// the same `sys.vertical_migrations` tracking enroll uses.
///
/// The `sql_dirs` filesystem scan remains only as a fallback for verticals
/// without self-describing binaries — no vertical ships one anymore.
///
/// This must be run BEFORE `vertical enroll` and BEFORE starting services.
/// Services assume their tables already exist — they do NOT create tables
/// on startup.
// DBX: per-database `public` helpers (RLS functions + extensions) — applied to
// every new vertical database at `vertical init` (platform.sql embeds the
// same definitions for db sentin8).
const PUBLIC_HELPERS_SQL: &str = include_str!("migrations/public_helpers.sql");

/// Local substrate SQL applied to every VERTICAL database at init/enroll
/// (VDC-5/VDC-6, design/sentin8-vertical-data-plane-contract.md §VDC.6):
/// Shield policy substrate + `sentin8_boot_policy_load` + the
/// `sys.vertical_services` registry replica.
const VERTICAL_SUBSTRATE_SQL: &str = include_str!("migrations/vertical_substrate.sql");

/// DBX (§6.6): ensure the vertical database exists (guarded CREATE DATABASE
/// on a maintenance connection), then return its URL.
async fn ensure_vertical_database(db_url: &str, vertical: &str) -> anyhow::Result<String> {
    if vertical == "sentin8" {
        return Ok(db_url.to_string()); // platform database — `db bootstrap` owns it
    }
    let safe = vertical
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !vertical.is_empty();
    anyhow::ensure!(safe, "invalid vertical database name: {vertical}");
    let base = {
        let trimmed = db_url.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(pos) => trimmed[..pos].to_string(),
            None => trimmed.to_string(),
        }
    };
    let maint_pool = sentin8::config::pg_pool::connect(&base).await?;
    let exists: bool =
        sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"#)
            .bind(vertical)
            .fetch_one(&maint_pool)
            .await?;
    if !exists {
        sqlx::query(&format!("CREATE DATABASE \"{vertical}\""))
            .execute(&maint_pool)
            .await?;
        println!("  created database \"{vertical}\"");
    }
    drop(maint_pool);
    Ok(format!("{base}/{vertical}"))
}

pub async fn init_vertical(path: &str) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let registry = load_registry(path)?;

    println!("Initializing vertical: {} ({})", registry.vertical, path);

    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());

    let vertical_root = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // DBX (§6.6): each vertical owns a DEDICATED DATABASE. The platform
    // (`sentin8`) vertical's database already exists (db bootstrap); every
    // other vertical gets its database created here — guarded CREATE
    // DATABASE (PostgreSQL has no IF NOT EXISTS), then the platform `public`
    // helper SQL + the vertical's roles/search_path/scope-map/tables inside
    // it. Roles are CLUSTER-WIDE, so creation is idempotent.
    let vertical_db = ensure_vertical_database(&db_url, &registry.vertical).await?;
    if registry.vertical != "sentin8" {
        let vpool = sentin8::config::pg_pool::connect(&vertical_db).await?;
        sqlx::raw_sql(PUBLIC_HELPERS_SQL).execute(&vpool).await?;
        // VDC-5/VDC-6 (design/sentin8-vertical-data-plane-contract.md
        // §VDC.6): provision the LOCAL substrate (Shield policy tables +
        // boot loader + registry replica) in the vertical database BEFORE
        // any service SQL — the hot-path reads a vertical service performs
        // (PolicyEngine boot-load, per-request relation/attr slices,
        // subdomain resolution) all stay on its OWN database.
        sqlx::raw_sql(VERTICAL_SUBSTRATE_SQL)
            .execute(&vpool)
            .await?;
        println!(
            "  provisioned public helpers + local substrate in \"{}\"",
            registry.vertical
        );
        drop(vpool);
    }
    let pool = sentin8::config::pg_pool::connect(&vertical_db).await?;
    // The PLATFORM pool — `cron.schedules` lives on db sentin8 (cron serves
    // the whole fleet); a vertical's declared schedules must seed THERE,
    // never into the vertical's own database (which has no cron schema —
    // the relation-not-exist abort class this connection prevents).
    let platform_pool = sentin8::config::pg_pool::connect(&db_url).await?;

    // Binary-sourced path (primary): SQL comes from the services' embedded
    // sql_migrations via --print-registration. Roles are created BEFORE SQL
    // so init.sql grant blocks (guarded by pg_roles EXISTS checks) never
    // silently skip (incident 2026-08-28).
    let mut total_applied = 0usize;
    // Certificate-identity rows (group DESIGN.md §3.2): (CN, role) pairs
    // collected during role creation, flushed into `pg_ident.conf` at the
    // end of the pass — the same one-pass role+binding provisioning the
    // Valkey ACL users get (§3.1).
    let mut ident_rows: Vec<(String, String)> = Vec::new();
    for svc in &registry.services {
        let binary = svc.binary.as_str();
        if binary.is_empty() {
            continue;
        }
        println!("  [binary] {binary}");

        // 1. Create PG roles before SQL.
        let pg_roles_json = run_print_registration(binary, "pg_roles", &vertical_root).await?;
        if let Some(roles) = pg_roles_json.as_ref().and_then(|v| v.as_array()) {
            for role_entry in roles {
                if let Some(obj) = role_entry.as_object() {
                    let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
                    let bypass_rls = obj
                        .get("bypass_rls")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    // DBX: no role may bypass RLS — reject the declaration.
                    anyhow::ensure!(
                        !bypass_rls,
                        "service {binary} declares bypass_rls=true for {role} — \
                         DBX forbids BYPASSRLS roles (architecture-principles §6.7)"
                    );
                    if !role.is_empty() {
                        // Role creation (group DESIGN.md §3.2): roles are
                        // PASSWORDLESS — the certificate identity map
                        // (`pg_ident.conf`) binds the workload's CN to the
                        // role, and PostgreSQL's `cert` auth method decides
                        // the connection. The row is written in the same
                        // pass (registration-driven — zero core vertical
                        // knowledge, §4.14 parity with the Valkey ACL
                        // provisioning).
                        let role_sql = format!(
                            "DO $$ BEGIN \
                             PERFORM 1 FROM pg_roles WHERE rolname = '{role}'; \
                             IF NOT FOUND THEN \
                                 CREATE ROLE {role} LOGIN NOBYPASSRLS; \
                             ELSE \
                                 ALTER ROLE {role} LOGIN NOBYPASSRLS; \
                             END IF; END $$;",
                            role = role
                        );
                        match sqlx::query(&role_sql).execute(&pool).await {
                            Ok(_) => {
                                println!(
                                    "    role '{role}' created/verified (certificate identity)"
                                )
                            }
                            Err(e) => {
                                eprintln!("    WARNING: failed to create PG role '{role}': {e}")
                            }
                        }
                        ident_rows.push((format!("m2m-{}", svc.service_type), role.to_string()));
                    }
                }
            }
        }

        // 2. Apply embedded SQL migrations (tracked in vertical_migrations).
        let sql_json = run_print_registration(binary, "sql", &vertical_root).await?;
        if let Some(migrations) = sql_json {
            let applied = apply_sql_migrations(
                &pool,
                &registry.vertical,
                &svc.service_type,
                &migrations,
                &sentin8_domain,
            )
            .await?;
            println!("    {applied} migration(s) applied from {binary}");
            total_applied += applied;
        }
    }

    // Filesystem fallback (legacy, REG-3): only when a service entry has no
    // resolved binary and the registry still declares sql_dirs. Kept for
    // pre-SELFREG verticals; no vertical ships a sql_dirs anymore.
    if registry.services.iter().any(|s| s.binary.is_empty()) {
        for sql_dir in &registry.sql_dirs {
            println!("  [legacy sql_dirs] {sql_dir}");
            let abs_dir = vertical_root.join(sql_dir);
            if !abs_dir.is_dir() {
                println!("    skipping (not found)");
                continue;
            }
            let mut sql_files: Vec<(String, std::path::PathBuf)> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&abs_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().is_some_and(|ext| ext == "sql") {
                        let filename = p
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        sql_files.push((filename, p));
                    }
                }
            }
            sql_files.sort_by(|a, b| {
                let priority = |name: &str| match name {
                    "init.sql" => 0,
                    "extended.sql" => 2,
                    _ => 3,
                };
                priority(&a.0)
                    .cmp(&priority(&b.0))
                    .then_with(|| a.0.cmp(&b.0))
                    .then_with(|| a.1.cmp(&b.1))
            });
            for (filename, file_path) in &sql_files {
                let sql = std::fs::read_to_string(file_path)
                    .map_err(|e| anyhow::anyhow!("read SQL {sql_dir}/{filename}: {e}"))?;
                let sql = sql
                    .replace(":'sentin8_domain'", &format!("'{}'", sentin8_domain))
                    .replace(":'sentin8.domain'", &format!("'{}'", sentin8_domain));
                println!("    applying {sql_dir}/{filename} ...");
                sqlx::raw_sql(&sql)
                    .execute(&pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("apply SQL {sql_dir}/{filename}: {e}"))?;
                total_applied += 1;
            }
        }
    }

    println!(
        "  Applied {} migration(s)/SQL file(s) for vertical '{}'",
        total_applied, registry.vertical
    );

    // Phase 28 (POLICY-CLI-2) + VDC-5: seed declarative Shield policy sets
    // into `policy_sets` (design/sentin8-policy-technical-design.md §3.2)
    // and ReBAC relation tuples into `policy_relations` (§3.1c).
    // Registration-declared sections win (SELFREG — the binary is the source
    // of truth). For the PLATFORM vertical `pool` is the platform DB and
    // the rows are platform-side (reload events emitted). For a NON-PLATFORM
    // vertical `pool` is the vertical DB — the rows go to its LOCAL
    // substrate (VDC-5: the service's Shield engine boot-loads from its own
    // database; substrate mode skips the platform-env lookup and the
    // outbox event). Event triggers, JSON-fallback policies, and the
    // registry replica are platform-side concerns — `vertical enroll` owns
    // them (it holds the platform pool).
    let is_platform = registry.vertical == "sentin8";
    for svc in &registry.services {
        if svc.binary.is_empty() {
            continue;
        }
        let policies_json = run_print_registration(&svc.binary, "policies", &vertical_root).await?;
        let relations_json =
            run_print_registration(&svc.binary, "relations", &vertical_root).await?;
        upsert_registration_policies(
            &pool,
            &svc.service_type,
            policies_json.as_ref(),
            relations_json.as_ref(),
            !is_platform,
        )
        .await?;
        let triggers_json =
            run_print_registration(&svc.binary, "event_triggers", &vertical_root).await?;
        if is_platform {
            upsert_registration_event_triggers(&pool, &svc.service_type, triggers_json.as_ref())
                .await?;
        }
        // Declarative schedules (SDD §2.4) — provisioned into
        // `cron.schedules` on the PLATFORM DB (cron serves the whole
        // fleet) regardless of which vertical declares them.
        let schedules_json =
            run_print_registration(&svc.binary, "schedules", &vertical_root).await?;
        upsert_registration_schedules(
            &platform_pool,
            &svc.service_type,
            &svc.subdomain,
            schedules_json.as_ref(),
        )
        .await?;
    }
    if is_platform {
        upsert_registry_policies(&pool, &registry).await?;
        upsert_registry_relations(&pool, &registry).await?;
    }

    println!("Vertical '{}' initialized successfully.", registry.vertical);
    // PostgreSQL certificate identity (§3.2): flush the collected
    // (CN, role) bindings into the identity map — the enroll/init pass is
    // the single convergence point for roles AND their identities. The
    // PLATFORM rows converge too: `db bootstrap` wrote them once, but the
    // file must self-heal after ANY reset/manual churn — every init/enroll
    // pass re-adds the fixed plane's rows idempotently.
    let mut all_rows = crate::db::platform_pg_ident_rows();
    all_rows.append(&mut ident_rows);
    crate::db::write_pg_ident_rows(&all_rows).await?;
    Ok(())
}

/// Resolve one enrollment path into a registry value (RS §6 composable
/// enrollment).
///
/// A path is either:
/// - a **repo directory** containing `service-registration.json` (the
///   per-repo fragment — one registry entry, self-describing; the repo's
///   `catalog.json` is picked up separately by captain's
///   `SENTIN8_CAPTAIN_CATALOG_PATHS`), or
/// - a **legacy aggregate** `vertical-registry.json` file.
///
/// Returns the loaded registry plus the effective path for error reporting.
fn load_registry_path(path: &str) -> anyhow::Result<VerticalRegistry> {
    let p = std::path::Path::new(path);
    // WARN-11 (inline apps): the fragment loader stamps every app entry
    // with the SOURCE REPO dir — composable enrollment merges fragments
    // into a temp aggregate and re-registers from there, and the inline
    // web-root join needs the app's OWN dir, not the temp file's parent.
    // (The `source_dir` field is skip-serialized when empty, so legacy
    // aggregates stay byte-stable.)
    let stamp = |mut reg: VerticalRegistry, source: &std::path::Path| {
        let dir = source.to_string_lossy().to_string();
        for app in reg.apps.iter_mut() {
            app.source_dir = dir.clone();
        }
        reg
    };
    if p.is_dir() {
        let frag = p.join("service-registration.json");
        let frag_path = frag.to_string_lossy().to_string();
        if !frag.exists() {
            // A vertical root WITHOUT per-repo fragments: fall back to the
            // legacy aggregate file inside it (compat with the old layout).
            let legacy = p.join("vertical-registry.json");
            if legacy.exists() {
                let reg = load_registry(&legacy.to_string_lossy())?;
                return Ok(stamp(reg, p));
            }
            anyhow::bail!(
                "directory {path} has neither service-registration.json nor vertical-registry.json"
            );
        }
        let reg = load_registry(&frag_path)?;
        Ok(stamp(reg, p))
    } else if p.is_file() {
        let parent = p
            .parent()
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let reg = load_registry(path)?;
        Ok(stamp(reg, &parent))
    } else {
        anyhow::bail!("path not found: {path}")
    }
}

/// Merge fragment registries into one aggregate registry for enrollment.
///
/// All fragments of the same vertical merge (services/apps/policies/…
/// concatenate); fragments of DIFFERENT verticals stay separate — each
/// runs its own enroll pass. Vertical-wide fields (`extra_env`, `valkey`,
/// `sql_dirs`) merge first-wins with a warning on conflict (a fragment
/// declaring vertical-wide env for a vertical it doesn't own would be a
/// defect).
pub async fn register_paths(paths: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(!paths.is_empty(), "no enrollment paths given");
    let mut by_vertical: Vec<(String, VerticalRegistry)> = Vec::new();
    for path in paths {
        let reg = load_registry_path(path)?;
        match by_vertical.iter_mut().find(|(v, _)| *v == reg.vertical) {
            Some((_, merged)) => {
                merged.services.extend(reg.services);
                merged.apps.extend(reg.apps);
                merged.policies.extend(reg.policies);
                merged.relations.extend(reg.relations);
                merged.consent_providers.extend(reg.consent_providers);
                merged.service_actions.extend(reg.service_actions);
                merged.error_codes.extend(reg.error_codes);
                merged.audit_findings.extend(reg.audit_findings);
                merged.admin_ui.extend(reg.admin_ui);
                merged.consent_flows.extend(reg.consent_flows);
                merged.cli_commands.extend(reg.cli_commands);
                merged.sql_dirs.extend(reg.sql_dirs);
                merged.verticals.extend(reg.verticals);
                for (k, val) in reg.extra_env {
                    merged.extra_env.entry(k).or_insert(val);
                }
                if merged.valkey.is_none() {
                    merged.valkey = reg.valkey;
                }
            }
            None => by_vertical.push((reg.vertical.clone(), reg)),
        }
    }
    println!(
        "Composable enrollment (RS §6): {} path(s) → {} vertical(s)",
        paths.len(),
        by_vertical.len()
    );
    // Persist each merged registry to a temp aggregate so the existing
    // enroll pipeline (catalog merge, app scan, binary --print-registration)
    // runs unchanged per vertical.
    for (vertical, reg) in &by_vertical {
        let merged_path = std::env::temp_dir().join(format!("sentin8-enroll-{vertical}.json"));
        let json = serde_json::to_string_pretty(reg)?;
        std::fs::write(&merged_path, json)?;
        let path_str = merged_path.to_string_lossy();
        register(&path_str).await?;
    }
    Ok(())
}

/// Enroll a vertical with the platform.
///
/// Registers services, apps, consent providers, error codes, and audit
/// findings. Does NOT apply SQL — use `vertical init` for that.
pub async fn register(path: &str) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let registry = load_registry(path)?;

    println!("Enrolling vertical: {} ({})", registry.vertical, path);
    println!("  Services: {}", registry.services.len());
    println!("  Vertical: {}", registry.vertical);
    println!("  Consent providers: {}", registry.consent_providers.len());
    println!("  Error codes: {}", registry.error_codes.len());
    println!("  Audit findings: {}", registry.audit_findings.len());
    // PostgreSQL certificate identity (group DESIGN.md §3.2): (CN, role)
    // pairs collected during the per-service role-creation loop, flushed
    // into `pg_ident.conf` after all services self-describe.
    let mut ident_rows: Vec<(String, String)> = Vec::new();

    // 1. Register known verticals in Valkey (for bff KNOWN_VERTICALS) —
    // over the certificate-identity TLS plane, presenting the operator's
    // admin pair (group DESIGN.md §3.1; the material comes from
    // `make infra-tls`).
    //
    // Fresh-boot ordering: the FIRST connection is made with the stock
    // default user's permissions — the `m2m-valkey-admin` ACL user does
    // not exist yet on a wiped Valkey (bootstrap's FLUSHALL aside, ACL
    // users live only in the AOF; `make infra-tls` cannot provision them).
    // Step 2b below provisions the fixed identities and DISABLES the
    // default user, which severs any connection still riding it — so the
    // durable admin connection is (re)opened AFTER provisioning, and the
    // pre-provision connection is used only for the read-shaped known-
    // verticals registration above. (GLIDE's reconnect would land on the
    // disabled default user — a fresh connection is the only sound path.)
    let valkey_url = std::env::var("VALKEY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(sentin8::config::service_valkey_url);
    let bootstrap_conn = open_admin_valkey_conn(&valkey_url).await?;

    for vertical in &registry.verticals {
        bootstrap_conn
            .custom_command(&["SADD", "captain:known_verticals", vertical])
            .await
            .map_err(|e| anyhow::anyhow!("SADD known verticals: {e}"))?;
    }
    // Also register the singular `vertical` field (SELFREG-11: `verticals` is
    // deprecated — `vertical` is the sole identifier going forward).
    if !registry.verticals.contains(&registry.vertical) {
        bootstrap_conn
            .custom_command(&["SADD", "captain:known_verticals", &registry.vertical])
            .await
            .map_err(|e| anyhow::anyhow!("SADD known verticals: {e}"))?;
    }
    println!(
        "  Registered known vertical '{}' in Valkey",
        registry.vertical
    );

    // 2. (Removed) Cross-service endpoint URLs — no longer needed.
    // Services derive URLs themselves via sentin8::config::platform_domain()
    // (e.g. `format!("https://{}", cfg.platform_domain("bank8:ledger"))`).
    // The old `captain:vertical_endpoint:*` Valkey keys were never read by
    // any service — the code was dead data.

    // 3. Register service definitions in PostgreSQL (for sys to
    // know which hostname prefixes and service types to create mappings for
    // when provisioning an org/env). This replaces the hardcoded list in
    // sys's domain_mapping.rs.
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    // Platform registry tables live in db sentin8.
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;
    // DBX (§6.6): per-service SQL applies INSIDE the vertical's database.
    let vertical_db = ensure_vertical_database(&db_url, &registry.vertical).await?;
    let vertical_pool = sentin8::config::pg_pool::connect(&vertical_db).await?;
    if registry.vertical != "sentin8" {
        sqlx::raw_sql(PUBLIC_HELPERS_SQL)
            .execute(&vertical_pool)
            .await?;
        // VDC-5/VDC-6: idempotent substrate convergence — enroll re-applies
        // the local substrate so a database created before this change (or
        // a partial init) converges without a full re-init.
        sqlx::raw_sql(VERTICAL_SUBSTRATE_SQL)
            .execute(&vertical_pool)
            .await?;
    }

    // Create the vertical services table if it doesn't exist (idempotent).
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.vertical_services (
            vertical TEXT NOT NULL,
            service_type TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            health_path TEXT NOT NULL DEFAULT '/v1/health',
            admin_ui JSONB,
            PRIMARY KEY (vertical, service_type)
        )"#,
    )
    .execute(&pool)
    .await?;

    // Add admin_ui column if it doesn't exist (for existing tables).
    sqlx::query(r#"ALTER TABLE vertical_services ADD COLUMN IF NOT EXISTS admin_ui JSONB"#)
        .execute(&pool)
        .await?;

    // Add NOTIFY trigger for domain resolver cache invalidation.
    // The proxy's DomainResolver loads known service types from this table.
    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION public.sentin8_notify_domain_changed() RETURNS trigger AS $$
           BEGIN
             PERFORM pg_notify('sentin8_domain_changed', '');
             RETURN NEW;
           END;
           $$ LANGUAGE plpgsql"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(r#"DROP TRIGGER IF EXISTS vertical_domain_notify ON sys.vertical_services"#)
        .execute(&pool)
        .await?;
    sqlx::query(
        r#"CREATE TRIGGER vertical_domain_notify
             AFTER INSERT OR UPDATE OR DELETE ON sys.vertical_services
             FOR EACH STATEMENT EXECUTE FUNCTION public.sentin8_notify_domain_changed()"#,
    )
    .execute(&pool)
    .await?;

    // SELFREG-8/9: For services with a `binary` field, use `--print-registration`
    // to get all registration data from the service itself. This is the
    // self-describing path — the service IS the source of truth.
    let vertical_root = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());

    // Create all registration tables (idempotent — always runs, even in
    // self-describing mode, because register_service_from_registration
    // writes to these tables).
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.consent_providers (
        vertical TEXT NOT NULL, feature TEXT NOT NULL, data_type TEXT NOT NULL,
        service_type TEXT NOT NULL, platform_domain_key TEXT NOT NULL,
        endpoint TEXT NOT NULL, scope TEXT NOT NULL, response_key TEXT NOT NULL,
        PRIMARY KEY (feature, data_type, vertical))"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.service_actions (
        vertical TEXT NOT NULL, action TEXT NOT NULL, service_type TEXT NOT NULL,
        platform_domain_key TEXT NOT NULL, method TEXT NOT NULL,
        endpoint TEXT NOT NULL, scope TEXT NOT NULL,
        PRIMARY KEY (action, vertical))"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.vertical_admin_scopes (
        vertical TEXT NOT NULL, service_type TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL, scope TEXT NOT NULL,
        PRIMARY KEY (vertical, service_type, role, scope))"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.vertical_error_codes (
        vertical TEXT NOT NULL, enum_name TEXT NOT NULL, error_code TEXT NOT NULL,
        status_code INT NOT NULL, PRIMARY KEY (vertical, enum_name))"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.vertical_audit_findings (
        id SERIAL PRIMARY KEY, vertical TEXT NOT NULL, finding TEXT NOT NULL,
        recommendation TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.consent_flows (
        vertical TEXT NOT NULL, flow_id TEXT NOT NULL, trigger_patterns JSONB NOT NULL,
        service_type TEXT NOT NULL, ui_endpoint TEXT NOT NULL,
        approve_endpoint TEXT NOT NULL, deny_endpoint TEXT NOT NULL,
        PRIMARY KEY (vertical, flow_id))"#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.cli_commands (
        vertical TEXT NOT NULL, command TEXT NOT NULL, subcommand TEXT NOT NULL,
        action TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
        scope TEXT NOT NULL, args JSONB NOT NULL DEFAULT '[]'::jsonb,
        PRIMARY KEY (vertical, command, subcommand, action))"#,
    )
    .execute(&pool)
    .await?;

    // 2b. Provision the Valkey certificate-identity plane's FIXED
    // identities (group DESIGN.md §3.1) FIRST — the per-service loop
    // below publishes the token-free registry map through the
    // registry-writer, so its ACL user (connect probes included) must
    // exist before the first publish. Per-WORKLOAD users are still
    // provisioned per service from each service's own `m2m_grants`.
    // The pre-provision bootstrap_conn (step 1) may still ride the stock
    // default user — provisioning DISABLES it, so the durable admin
    // connection is opened fresh here (CN → the now-existing admin user).
    provision_valkey_admin_users(&bootstrap_conn).await?;
    let valkey_conn = open_admin_valkey_conn(&valkey_url).await?;

    let mut self_described = 0;
    // REG-7: service_types that successfully self-described — the legacy
    // JSON loop below must skip exactly these (binary is now defaulted to
    // service_type, so "has binary" no longer identifies them).
    let mut self_described_types: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for svc in &registry.services {
        let binary = svc.binary.as_str();
        if binary.is_empty() {
            continue;
        }

        println!("  Self-describing: {binary} --print-registration");

        // a. Get service info.
        let service_json = match run_print_registration(binary, "service", &vertical_root).await? {
            Some(j) => j,
            None => {
                println!("    (no --print-registration support, falling back to registry JSON)");
                continue;
            }
        };

        // a2. Create the service's PostgreSQL role(s) BEFORE applying SQL
        // migrations. Service init.sql grant blocks are guarded with
        // `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ...)` — if the
        // role does not exist yet, the grants silently skip and the service
        // crash-loops on startup with "permission denied" (incident
        // 2026-08-28: sentin8-auth on signing_keys).
        let pg_roles_json_early =
            run_print_registration(binary, "pg_roles", &vertical_root).await?;
        if let Some(roles) = pg_roles_json_early.as_ref().and_then(|v| v.as_array()) {
            for role_entry in roles {
                if let Some(obj) = role_entry.as_object() {
                    let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
                    let bypass_rls = obj
                        .get("bypass_rls")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    // DBX: no role may bypass RLS — reject the declaration.
                    anyhow::ensure!(
                        !bypass_rls,
                        "service {binary} declares bypass_rls=true for {role} — \
                         DBX forbids BYPASSRLS roles (architecture-principles §6.7)"
                    );
                    if !role.is_empty() {
                        // Cluster-wide role creation (group DESIGN.md §3.2):
                        // PASSWORDLESS — the certificate identity map binds
                        // the workload CN to the role (`cert` auth decides
                        // the connection; no SCRAM hash exists to converge).
                        let create_sql = format!(
                            "DO $$ BEGIN PERFORM 1 FROM pg_roles WHERE rolname = '{role}'; \
                             IF NOT FOUND THEN \
                                 CREATE ROLE {role} LOGIN NOBYPASSRLS; \
                             ELSE \
                                 ALTER ROLE {role} LOGIN NOBYPASSRLS; \
                             END IF; END $$;",
                            role = role
                        );
                        match sqlx::query(&create_sql).execute(&pool).await {
                            Ok(_) => println!("    PostgreSQL role '{}' created/verified", role),
                            Err(e) => {
                                eprintln!("    WARNING: failed to create PG role '{}': {}", role, e)
                            }
                        }
                        ident_rows.push((format!("m2m-{}", svc.service_type), role.to_string()));
                        // DBX: per-database search_path + grants in the VERTICAL
                        // database (leaf schema = service identity's last segment).
                        let leaf = svc
                            .service_type
                            .rsplit(':')
                            .next()
                            .unwrap_or(&svc.service_type);
                        // Only set it when the role has NO search_path
                        // configured yet — platform.sql may declare an
                        // extended one for platform services that need
                        // declared cross-schema access (e.g. sys provisions
                        // RBAC on auth's tables: `sys, auth, public`).
                        // Enroll fills verticals; it never clobbers.
                        // The default is `{leaf}, {vertical}, public` — the
                        // vertical schema is SECOND so a vertical that hosts
                        // all its services' tables in one shared schema
                        // (bank8: tables live in `bank8.ledger_products`, not
                        // `ledger.*`) still resolves after a role recreation
                        // (the init.sql migration declaring the extended path
                        // is version-tracked and never re-runs).
                        let existing_sp: Option<(Option<String>,)> = sqlx::query_as(&format!(
                            "SELECT unnest(rolconfig) FILTER (WHERE setting LIKE 'search_path=%') FROM pg_roles WHERE rolname = '{}'",
                            role
                        ))
                        .fetch_optional(&vertical_pool)
                        .await
                        .ok()
                        .flatten();
                        if existing_sp.is_none() {
                            let _ = sqlx::query(&format!(
                                "ALTER ROLE {} SET search_path = {}, {}, public",
                                role, leaf, registry.vertical
                            ))
                            .execute(&vertical_pool)
                            .await;
                        }
                        // Declared cross-schema grants are NOT applied here:
                        // a grant may target a table owned by a service that
                        // enrolls LATER in the registry (registry order is not
                        // dependency order — bff declares reads on
                        // sys.environments; sys owns it and enrolls after bff),
                        // so an inline GRANT hits undefined_table on a fresh
                        // bootstrap and never converges. They run in the
                        // phase-2 post-loop pass below, after ALL self-described
                        // SQL has been applied (registration README §6 grant
                        // convergence semantics; grant-drift incident).
                    }
                }
            }
        }

        // b. Apply SQL migrations (SELFREG-9) — DBX: inside the VERTICAL database.
        if let Some(sql_json) = run_print_registration(binary, "sql", &vertical_root).await? {
            let applied = apply_sql_migrations(
                &vertical_pool,
                &registry.vertical,
                &svc.service_type,
                &sql_json,
                &sentin8_domain,
            )
            .await?;
            println!("    Applied {applied} SQL migrations");
        }

        // c. Get admin_ui.
        let admin_ui_json = run_print_registration(binary, "admin_ui", &vertical_root).await?;

        // d. Get admin_scopes.
        let admin_scopes_json =
            run_print_registration(binary, "admin_scopes", &vertical_root).await?;

        // e. Get error_codes.
        let error_codes_json =
            run_print_registration(binary, "error_codes", &vertical_root).await?;

        // f. Get consent.
        let consent_json = run_print_registration(binary, "consent", &vertical_root).await?;

        // f2. Get audit_findings (SELFREG-16).
        let audit_findings_json =
            run_print_registration(binary, "audit_findings", &vertical_root).await?;

        // f3. Get service_actions (SELFREG-17).
        let service_actions_json =
            run_print_registration(binary, "service_actions", &vertical_root).await?;

        // f3a. Get M2M DCR scope grants (self-registration §3.11).
        let m2m_grants_json = run_print_registration(binary, "m2m_grants", &vertical_root).await?;

        // f4. Get openapi spec and derive CLI commands from it (SELFREG-18).
        let openapi_json = run_print_registration(binary, "openapi", &vertical_root).await?;

        // f5. Get pg_roles (the certificate-identity bindings: the role's
        // database + scope provenance; the TLS identity row itself is
        // written at role creation in step a2, group DESIGN.md §3.2).
        let pg_roles_json = run_print_registration(binary, "pg_roles", &vertical_root).await?;
        if let Some(roles) = pg_roles_json.as_ref().and_then(|v| v.as_array()) {
            for role_entry in roles {
                if let Some(obj) = role_entry.as_object() {
                    // Scope provenance (registration audit) — the
                    // connection itself is certificate-decided (§3.2).
                    let _scope = obj.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                    let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
                    let bypass_rls = obj
                        .get("bypass_rls")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    // DBX: reject BYPASSRLS declarations.
                    anyhow::ensure!(
                        !bypass_rls,
                        "service {binary} declares bypass_rls=true for {role} — \
                         DBX forbids BYPASSRLS roles (architecture-principles §6.7)"
                    );
                    if !role.is_empty() {
                        // Cluster-wide role creation (idempotent, PASSWORDLESS —
                        // group DESIGN.md §3.2) — from the platform pool
                        // (roles are cluster-level).
                        let create_sql = format!(
                            "DO $$ BEGIN PERFORM 1 FROM pg_roles WHERE rolname = '{}'; \
                             IF NOT FOUND THEN CREATE ROLE {} LOGIN NOBYPASSRLS; END IF; END $$;",
                            role, role
                        );
                        match sqlx::query(&create_sql).execute(&pool).await {
                            Ok(_) => println!("    PostgreSQL role '{}' created/verified", role),
                            Err(e) => {
                                eprintln!("    WARNING: failed to create PG role '{}': {}", role, e)
                            }
                        }
                    }
                }
            }
        }

        // (Phase 2 — declarative policy/relation/trigger seeding moved AFTER
        // the loop: REG-13, incident 2026-09-07. The policy tables and the
        // bootstrap env row are owned by sys's init.sql and the policy
        // events are inbox-first into bus's sentin8_bus_inbox, so seeding
        // here would reference tables that do not exist yet — registry
        // order is not a dependency order.)

        // g. If the registry JSON declares a subdomain override (non-default,
        // REG-7: empty means unset → binary's own emission wins), inject it
        // into the service_json so it takes precedence over the binary's
        // output (which no longer emits subdomain).
        let mut service_json = service_json;
        if !svc.subdomain.is_empty() {
            if let Some(obj) = service_json.as_object_mut() {
                obj.insert(
                    "subdomain".to_string(),
                    serde_json::Value::String(svc.subdomain.clone()),
                );
            }
        }

        // h. Register everything.
        register_service_from_registration(
            &pool,
            &registry.vertical,
            &service_json,
            admin_ui_json.as_ref(),
            admin_scopes_json.as_ref(),
            error_codes_json.as_ref(),
            consent_json.as_ref(),
            audit_findings_json.as_ref(),
            service_actions_json.as_ref(),
            m2m_grants_json.as_ref(),
            openapi_json.as_ref(),
            registry.valkey.as_ref(),
            &valkey_conn,
        )
        .await?;

        self_described += 1;
        self_described_types.insert(svc.service_type.clone());
    }

    if self_described > 0 {
        println!("  Self-described {self_described} services via --print-registration");
    }

    // Phase 2 — declared cross-schema grants (registration README §6 grant
    // convergence): applied AFTER all self-described SQL above, never inline
    // per-service. A declared grant may reference a table owned by a service
    // that enrolls LATER in the registry (registry order is not dependency
    // order — bff declares reads on sys.environments, sys owns it and runs
    // after bff), so an inline GRANT hits undefined_table on a fresh
    // bootstrap and the grant never converges (grant-drift incident: the
    // bff/auth/storage/stat/proxy SELECTs on sys.environments/organizations/
    // app_instances were declared but absent, and the BFF D3 auth-env match
    // rejected every /auth/callback with 403). GRANT is an idempotent
    // no-op re-grant, so this pass is the single convergence point for
    // fresh AND drifted databases alike.
    let mut grants_applied = 0usize;
    let mut grants_failed = 0usize;
    for svc in &registry.services {
        if !self_described_types.contains(&svc.service_type) {
            continue;
        }
        let binary = svc.binary.as_str();
        let pg_roles_json = run_print_registration(binary, "pg_roles", &vertical_root).await?;
        let Some(roles) = pg_roles_json.as_ref().and_then(|v| v.as_array()) else {
            continue;
        };
        for role_entry in roles {
            let Some(obj) = role_entry.as_object() else {
                continue;
            };
            let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role.is_empty() {
                continue;
            }
            // Grants apply in the VERTICAL database (the database the
            // service's role reads in — platform roles read db sentin8,
            // vertical roles their own vertical DB; both pools converge
            // here for the sentin8 vertical where pool == vertical_pool).
            if let Some(grants) = obj.get("cross_schema_grants").and_then(|v| v.as_array()) {
                for g in grants {
                    let gs = g.get("schema").and_then(|v| v.as_str()).unwrap_or("");
                    let gt = g.get("table").and_then(|v| v.as_str()).unwrap_or("");
                    let gp = g
                        .get("privilege")
                        .and_then(|v| v.as_str())
                        .unwrap_or("SELECT");
                    if gs.is_empty() || gt.is_empty() {
                        continue;
                    }
                    // Two SEPARATE statements — sqlx's extended protocol
                    // permits one command per prepared query.
                    let usage = sqlx::query(&format!("GRANT USAGE ON SCHEMA {} TO {}", gs, role))
                        .execute(&vertical_pool)
                        .await;
                    let table = sqlx::query(&format!("GRANT {} ON {}.{} TO {}", gp, gs, gt, role))
                        .execute(&vertical_pool)
                        .await;
                    match (usage, table) {
                        (Ok(_), Ok(_)) => grants_applied += 1,
                        (Err(e), _) | (_, Err(e)) => {
                            grants_failed += 1;
                            eprintln!(
                                "    WARNING: cross-schema grant {gs}.{gt} to {role} failed: {e}"
                            );
                        }
                    }
                }
            }
        }
    }
    if grants_applied > 0 || grants_failed > 0 {
        println!(
            "  Applied {grants_applied} declared cross-schema grants (phase 2), {grants_failed} failed"
        );
    }

    // Phase 2 — declarative seeding (REG-13, incident 2026-09-07): policy
    // sets, relation tuples, and event triggers are seeded AFTER all
    // self-described SQL above has been applied, never inline per-service.
    // The policy tables (`sys.policy_sets` / `_relations`) and
    // the bootstrap env row are owned by sys's init.sql and the policy
    // events are inbox-first into bus's `bus.inbox`; registry order
    // is not a dependency order (auth declares policies and runs first,
    // sys is 12th), so an inline seed references tables that do not exist
    // yet on a fresh database. Mirrors the two-phase pattern `vertical
    // init` already used.
    for svc in &registry.services {
        if !self_described_types.contains(&svc.service_type) {
            continue;
        }
        let binary = svc.binary.as_str();
        let policies_json = run_print_registration(binary, "policies", &vertical_root).await?;
        let relations_json = run_print_registration(binary, "relations", &vertical_root).await?;
        upsert_registration_policies(
            &pool,
            &svc.service_type,
            policies_json.as_ref(),
            relations_json.as_ref(),
            false,
        )
        .await?;
        // VDC-5: seed the SAME rows into the vertical DB's local substrate
        // (the service's Shield engine boot-loads from its OWN database).
        if registry.vertical != "sentin8" {
            upsert_registration_policies(
                &vertical_pool,
                &svc.service_type,
                policies_json.as_ref(),
                relations_json.as_ref(),
                true,
            )
            .await?;
        }
        // Seed declarative event triggers here too — enroll-only runs used
        // to drop them (init seeded them, enroll did not).
        let triggers_json =
            run_print_registration(binary, "event_triggers", &vertical_root).await?;
        upsert_registration_event_triggers(&pool, &svc.service_type, triggers_json.as_ref())
            .await?;
        // Declarative schedules (SDD §2.4) — same coverage rule as the
        // triggers: enroll-only runs provision them too.
        let schedules_json = run_print_registration(binary, "schedules", &vertical_root).await?;
        upsert_registration_schedules(
            &pool,
            &svc.service_type,
            &svc.subdomain,
            schedules_json.as_ref(),
        )
        .await?;
    }

    // Legacy JSON-based registration — only for services that did NOT
    // successfully self-describe above (binary missing on disk or no
    // --print-registration support). When all services self-describe,
    // this block is skipped (SELFREG-20).
    let has_legacy = registry
        .services
        .iter()
        .any(|s| !self_described_types.contains(&s.service_type));
    if has_legacy {
        // Build admin_ui lookup by service suffix.
        let admin_ui_json: Option<serde_json::Value> = if !registry.admin_ui.is_empty() {
            Some(serde_json::to_value(&registry.admin_ui).unwrap_or(serde_json::Value::Null))
        } else {
            None
        };

        for svc in &registry.services {
            // Skip services that successfully self-described above
            // (REG-7: binary now defaults to service_type, so presence of
            // a binary no longer distinguishes the self-described ones).
            if self_described_types.contains(&svc.service_type) {
                continue;
            }
            // Find the matching admin_ui entry for this service.
            // Match by exact service_type or by identity suffix (e.g.
            // "bank8:ledger" matches admin_ui entry "service": "bank8:ledger"
            // or "service": "ledger" with service_type "bank8:ledger").
            let svc_admin_ui = admin_ui_json.as_ref().and_then(|arr| {
                arr.as_array().and_then(|a| {
                    a.iter().find(|entry| {
                        entry
                            .get("service")
                            .and_then(|s| s.as_str())
                            .map(|s| {
                                svc.service_type == s
                                    || svc.service_type.ends_with(&format!(":{s}"))
                            })
                            .unwrap_or(false)
                    })
                })
            });

            let subdomain = if svc.subdomain.is_empty() {
                &svc.service_type
            } else {
                &svc.subdomain
            };
            let health_path = svc.health_path.as_deref().unwrap_or("/v1/health");

            sqlx::query(
            r#"INSERT INTO sys.vertical_services (vertical, service_type, subdomain, health_path, admin_ui)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (vertical, service_type) DO UPDATE
                 SET subdomain = EXCLUDED.subdomain,
                     health_path = EXCLUDED.health_path,
                     admin_ui = EXCLUDED.admin_ui"#,
        )
        .bind(&registry.vertical)
        .bind(&svc.service_type)
        .bind(subdomain)
        .bind(health_path)
        .bind(svc_admin_ui)
        .execute(&pool)
        .await?;
        }
        let legacy_count = registry
            .services
            .iter()
            .filter(|s| !self_described_types.contains(&s.service_type))
            .count();
        println!(
            "  Registered {} service definitions from registry JSON ({} self-described)",
            legacy_count, self_described
        );

        // 4. Register consent data providers in PostgreSQL (for auth to
        // call vertical services during FDX/consent flows without hardcoding
        // service URLs, paths, or scopes).
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.consent_providers (
            vertical TEXT NOT NULL,
            feature TEXT NOT NULL,
            data_type TEXT NOT NULL,
            service_type TEXT NOT NULL,
            platform_domain_key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            scope TEXT NOT NULL,
            response_key TEXT NOT NULL,
            PRIMARY KEY (feature, data_type, vertical)
        )"#,
        )
        .execute(&pool)
        .await?;

        // Clear old providers for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.consent_providers WHERE vertical = $1")
            .bind(&registry.vertical)
            .execute(&pool)
            .await?;

        for cp in &registry.consent_providers {
            sqlx::query(
            r#"INSERT INTO sys.consent_providers (vertical, feature, data_type, service_type, platform_domain_key, endpoint, scope, response_key)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(&registry.vertical)
        .bind(&cp.feature)
        .bind(&cp.data_type)
        .bind(&cp.service_type)
        .bind(&cp.platform_domain_key)
        .bind(&cp.endpoint)
        .bind(&cp.scope)
        .bind(&cp.response_key)
        .execute(&pool)
        .await?;
        }
        println!(
            "  Registered {} consent providers in PostgreSQL",
            registry.consent_providers.len()
        );

        // 5. Register service actions in PostgreSQL (for bff and other
        // sentin8 services to call vertical services without hardcoding URLs,
        // endpoints, or scopes).
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.service_actions (
            vertical TEXT NOT NULL,
            action TEXT NOT NULL,
            service_type TEXT NOT NULL,
            platform_domain_key TEXT NOT NULL,
            method TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            scope TEXT NOT NULL,
            PRIMARY KEY (action, vertical)
        )"#,
        )
        .execute(&pool)
        .await?;

        // Clear old actions for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.service_actions WHERE vertical = $1")
            .bind(&registry.vertical)
            .execute(&pool)
            .await?;

        for sa in &registry.service_actions {
            sqlx::query(
            r#"INSERT INTO sys.service_actions (vertical, action, service_type, platform_domain_key, method, endpoint, scope)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(&registry.vertical)
        .bind(&sa.action)
        .bind(&sa.service_type)
        .bind(&sa.platform_domain_key)
        .bind(&sa.method)
        .bind(&sa.endpoint)
        .bind(&sa.scope)
        .execute(&pool)
        .await?;
        }
        println!(
            "  Registered {} service actions in PostgreSQL",
            registry.service_actions.len()
        );

        // NOTE: admin scopes are NOT written from registry JSON here —
        // `AdminScope` vocabulary comes exclusively from each service's
        // `--print-registration --section=admin_scopes` output (written by
        // `register_service_from_registration`, which handles both the
        // tuple and object JSON shapes). No registry JSON declares
        // `admin_scopes` anymore (REG-12): a JSON-side write path would
        // duplicate the vocabulary and drift from the handlers' gate scopes
        // (the 2026-09-06 post:write 403 incident).

        // 7. Register error codes in PostgreSQL.

        // Create the error codes table if it doesn't exist (idempotent).
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.vertical_error_codes (
            vertical TEXT NOT NULL,
            enum_name TEXT NOT NULL,
            error_code TEXT NOT NULL,
            status_code INT NOT NULL,
            PRIMARY KEY (vertical, enum_name)
        )"#,
        )
        .execute(&pool)
        .await?;

        for ec in &registry.error_codes {
            sqlx::query(
            r#"INSERT INTO sys.vertical_error_codes (vertical, enum_name, error_code, status_code)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (vertical, enum_name) DO UPDATE
                 SET error_code = EXCLUDED.error_code, status_code = EXCLUDED.status_code"#,
        )
        .bind(&registry.vertical)
        .bind(&ec.r#enum)
        .bind(&ec.code)
        .bind(ec.status_code as i32)
        .execute(&pool)
        .await?;
        }
        println!(
            "  Registered {} error codes in PostgreSQL",
            registry.error_codes.len()
        );

        // 4. Register audit findings in PostgreSQL.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.vertical_audit_findings (
            id SERIAL PRIMARY KEY,
            vertical TEXT NOT NULL,
            finding TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )"#,
        )
        .execute(&pool)
        .await?;

        // Clear old findings for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.vertical_audit_findings WHERE vertical = $1")
            .bind(&registry.vertical)
            .execute(&pool)
            .await?;

        for af in &registry.audit_findings {
            sqlx::query(
                r#"INSERT INTO sys.vertical_audit_findings (vertical, finding, recommendation)
               VALUES ($1, $2, $3)"#,
            )
            .bind(&registry.vertical)
            .bind(&af.finding)
            .bind(&af.recommendation)
            .execute(&pool)
            .await?;
        }
        println!(
            "  Registered {} audit findings in PostgreSQL",
            registry.audit_findings.len()
        );

        // 8. Register consent flows in PostgreSQL (§4.16.2).
        // Each consent flow defines a trigger pattern, the vertical service
        // that owns the consent UI, and the RFW endpoints.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.consent_flows (
            vertical           TEXT NOT NULL,
            flow_id            TEXT NOT NULL,
            trigger_patterns   JSONB NOT NULL,
            service_type       TEXT NOT NULL,
            ui_endpoint        TEXT NOT NULL,
            approve_endpoint   TEXT NOT NULL,
            deny_endpoint      TEXT NOT NULL,
            PRIMARY KEY (vertical, flow_id)
        )"#,
        )
        .execute(&pool)
        .await?;

        // Clear old consent flows for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.consent_flows WHERE vertical = $1")
            .bind(&registry.vertical)
            .execute(&pool)
            .await?;

        for cf in &registry.consent_flows {
            sqlx::query(
            r#"INSERT INTO sys.consent_flows (vertical, flow_id, trigger_patterns, service_type, ui_endpoint, approve_endpoint, deny_endpoint)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (vertical, flow_id) DO UPDATE
                 SET trigger_patterns = EXCLUDED.trigger_patterns,
                     service_type = EXCLUDED.service_type,
                     ui_endpoint = EXCLUDED.ui_endpoint,
                     approve_endpoint = EXCLUDED.approve_endpoint,
                     deny_endpoint = EXCLUDED.deny_endpoint"#,
        )
        .bind(&registry.vertical)
        .bind(&cf.id)
        .bind(serde_json::to_value(&cf.trigger_patterns).unwrap_or(serde_json::Value::Array(vec![])))
        .bind(&cf.service_type)
        .bind(&cf.ui_endpoint)
        .bind(&cf.approve_endpoint)
        .bind(&cf.deny_endpoint)
        .execute(&pool)
        .await?;
        }
        println!(
            "  Registered {} consent flows in PostgreSQL",
            registry.consent_flows.len()
        );

        // 10. Register CLI commands in PostgreSQL (design §9.1).
        // Each command is a self-contained {command, subcommand, action, method,
        // path, scope, args} entry. The CLI's generic executor reads these at
        // runtime — no hardcoded service subcommands in the CLI binary.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sys.cli_commands (
            vertical      TEXT NOT NULL,
            command       TEXT NOT NULL,
            subcommand    TEXT NOT NULL,
            action        TEXT NOT NULL,
            method        TEXT NOT NULL,
            path          TEXT NOT NULL,
            scope         TEXT NOT NULL,
            args          JSONB NOT NULL DEFAULT '[]'::jsonb,
            PRIMARY KEY (vertical, command, subcommand, action)
        )"#,
        )
        .execute(&pool)
        .await?;

        // Clear old CLI commands for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.cli_commands WHERE vertical = $1")
            .bind(&registry.vertical)
            .execute(&pool)
            .await?;

        for cmd in &registry.cli_commands {
            sqlx::query(
            r#"INSERT INTO sys.cli_commands (vertical, command, subcommand, action, method, path, scope, args)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (vertical, command, subcommand, action) DO UPDATE
                 SET method = EXCLUDED.method,
                     path = EXCLUDED.path,
                     scope = EXCLUDED.scope,
                     args = EXCLUDED.args"#,
        )
        .bind(&registry.vertical)
        .bind(&cmd.command)
        .bind(&cmd.subcommand)
        .bind(&cmd.action)
        .bind(&cmd.method)
        .bind(&cmd.path)
        .bind(&cmd.scope)
        .bind(serde_json::to_value(&cmd.args).unwrap_or(serde_json::Value::Array(vec![])))
        .execute(&pool)
        .await?;
        }
        println!(
            "  Registered {} CLI commands in PostgreSQL",
            registry.cli_commands.len()
        );
    } // end of `if has_legacy` block

    // 9. Register apps in PostgreSQL + Valkey.
    // Legacy: apps from registry JSON `apps[]` array (only in legacy mode).
    // Self-describing: apps scanned from `apps/*/app.json` files (always runs).
    if has_legacy && !registry.apps.is_empty() {
        register_apps(&registry, path, &valkey_conn, &pool).await?;
    }
    // SELFREG-10: Scan apps/*/app.json for self-describing apps (always runs).
    let app_json_count = register_apps_from_dir(
        path,
        &registry.apps,
        &registry.apps_dir,
        &valkey_conn,
        &pool,
    )
    .await?;

    println!(
        "  Registered {} apps from app.json ({} legacy)",
        app_json_count,
        if has_legacy { registry.apps.len() } else { 0 }
    );

    // 10. Merge catalog entries into captain's live catalog if captain is running.
    // This tells the running captain process how to spawn the newly enrolled
    // services (binary path, start_priority, use_http_health). If captain
    // isn't running (fresh start), captain will load the catalog at startup.
    merge_into_captain(&registry, path).await;

    // (The fixed Valkey identities were provisioned at step 2b — BEFORE
    // the per-service loop, because the loop's registry-map publishes
    // ride the registry-writer identity.)

    // 12. Reconcile generic per-service role grants (F1 hardening).
    // platform.sql's grants run during `db reset` — BEFORE vertical roles
    // and late-created tables exist. This pass re-applies the generic,
    // non-vertical grants for every *_service role:
    //   - search_path (sentin8 first, so unqualified table names resolve)
    //   - USAGE on schemas public + sentin8
    //   - inbox INSERT/SELECT (every service emits events)
    //   - audit_events INSERT
    //   - SELECT on CLI-created registry tables (consent_flows,
    //     consent_providers, service_actions, vertical_services, ...)
    //     that auth/sys/BFF read cross-service at request time
    // Table-specific grants remain owned by each service's init.sql and
    // platform.sql; this pass only fills the generic gaps. RLS still
    // scopes every row.
    {
        println!("  Applying generic service-role grants ...");
        sqlx::query(
            r#"DO $$
DECLARE
    role_name TEXT;
    roles TEXT[] := ARRAY[]::TEXT[];
    platform_roles TEXT[] := ARRAY[]::TEXT[];
BEGIN
    SELECT array_agg(rolname) INTO roles
    FROM pg_roles
    WHERE rolname LIKE '%_service' AND rolname NOT LIKE 'pg_%';
    IF array_length(roles, 1) IS NULL THEN
        RETURN;
    END IF;
    -- TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7)
    -- + VDC-1: split platform from vertical domain roles. Vertical roles
    -- are STRUCTURALLY locked out of the platform database: REVOKE
    -- CONNECT means no vertical process can even open a connection to db
    -- `sentin8` (belt to the DSN fail-fast suspenders) — and they hold
    -- zero platform-table grants (the database-free TLS resolver removed
    -- the hostname-table need; the Shield substrate + registry replica
    -- live in the vertical's OWN database, VDC-5/VDC-6). The rejected
    -- `{vertical}_tls_ingress` roles from an earlier draft are dropped.
    FOREACH role_name IN ARRAY roles LOOP
        IF role_name LIKE 'sentin8\_%\_service' THEN
            platform_roles := platform_roles || role_name;
        ELSE
            -- Vertical role: drop any stale `{vertical}_tls_ingress` role
            -- from the REJECTED earlier draft (a vertical must not hold ANY
            -- platform-database access; TLS-RLS-4 made it unnecessary).
            -- CONNECT is NOT granted to vertical roles anywhere — the
            -- platform-DB PUBLIC revoke in platform.sql is the boundary.
            -- `IF EXISTS` covers the already-dropped case; a role that
            -- still owns objects fails LOUD (an operator must resolve it).
            EXECUTE format('DROP ROLE IF EXISTS %I',
                           split_part(role_name, '_', 1) || '_tls_ingress');
        END IF;
    END LOOP;
    IF array_length(platform_roles, 1) IS NULL THEN
        RETURN;
    END IF;
    -- Platform-database CONNECT boundary (platform.sql owns the base
    -- revoke + grants; this pass re-grants CONNECT to platform roles as the
    -- idempotent convergence point after a re-bootstrap).
    FOREACH role_name IN ARRAY platform_roles LOOP
        EXECUTE format('GRANT CONNECT ON DATABASE sentin8 TO %I', role_name);
    END LOOP;
    -- DBX (§6.6): per-service search_path is set per role at role creation
    -- (`ALTER ROLE ... SET search_path = {service}, public` in the vertical
    -- database). This legacy blanket override is retired — roles keep their
    -- per-service paths.
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %s', array_to_string(platform_roles, ', '));
    -- Registry reads (sys schema, db sentin8): platform domain roles only.
    EXECUTE format('GRANT USAGE ON SCHEMA sys TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.consent_flows TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.consent_providers TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.service_actions TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.vertical_services TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.vertical_admin_scopes TO %s', array_to_string(platform_roles, ', '));
    -- TLS-RLS-4: the embedded HostContextResolver is DATABASE-FREE —
    -- hostname resolution rides Sys `GET /v1/resolve/hostname` (M2M
    -- `sentin8:sys:instances:read`). NO service role holds hostname-table
    -- grants for the library path anymore (the former TLS-RLS-3 grants
    -- are retired).
    -- Shield substrate (principles §6.6a sanctioned exception): PLATFORM
    -- services' roles read the platform policy tables per request
    -- (crates/policy/src/substrate.rs). Vertical services read their LOCAL
    -- substrate copies (VDC-5: policy tables provisioned in the vertical
    -- DB, seeded at enroll into the vertical pool).
    EXECUTE format('GRANT SELECT ON sys.policy_relations TO %s', array_to_string(platform_roles, ', '));
    EXECUTE format('GRANT SELECT ON sys.policy_principal_attrs TO %s', array_to_string(platform_roles, ', '));
    -- Shield self-heal seed (group DESIGN.md §3.2 "Shield substrate
    -- grants"): the runtime's sync-reload-on-empty-coverage may run inside
    -- ANY platform service's request path, seeding a fresh env's template
    -- sets through the CALLING service's own role (auth's provisioning
    -- endpoint exercises it at env creation, before the event-driven
    -- env-init refresh lands). Mirrors the vertical substrate's VDC-6
    -- loop: SELECT + INSERT + UPDATE only (enroll remains the only DELETE
    -- path); RLS (`sentin8_context_initialized()` WITH CHECK) bounds every
    -- write to an initialized tenant context.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON sys.policy_sets TO %s', array_to_string(platform_roles, ', '));
    -- App reads merged tenant branding (Story 12.2.23) — the sys.branding
    -- grant predates app's adoption of merged branding; re-applied here so
    -- app_service keeps SELECT after re-bootstrap.
    EXECUTE format('GRANT SELECT ON sys.branding TO sentin8_app_service');
    -- DB tenant-table DDL (db design "Table placement"): the db service
    -- creates/alters dynamic tenant tables in ITS OWN schema under its own
    -- role — the CREATE privilege is its declared grant. Re-applied here so
    -- a re-bootstrap converges (platform.sql/init.sql also declare it).
    EXECUTE format('GRANT CREATE ON SCHEMA db TO sentin8_db_service');
EXCEPTION WHEN undefined_table THEN NULL;
END $$;"#,
        )
        .execute(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("generic service-role grants: {e}"))?;
    }

    // Registry-fallback policy sets / relations (design §3.2): services
    // without self-describing binaries (bff, proxy, web, captain) declare
    // their sets as vertical-wide `policies`/`relations` entries with an
    // explicit `service`. Idempotent — platform rows overwrite, tenant rows
    // never touched.
    upsert_registry_policies(&pool, &registry).await?;
    upsert_registry_relations(&pool, &registry).await?;
    // VDC-6: replicate the runtime registry rows into the vertical DB (the
    // `sys.vertical_services` replica read hot by `sentin8-config` on the
    // service's own pool).
    if registry.vertical != "sentin8" {
        replicate_registry_to_substrate(&pool, &vertical_pool).await?;
    }

    println!("Vertical '{}' enrolled successfully.", registry.vertical);
    // PostgreSQL certificate identity (§3.2): flush the collected
    // (CN, role) bindings into the identity map — a future vertical's
    // roles bind with zero platform-side knowledge of the vertical. The
    // PLATFORM rows converge too (self-healing after any reset — see the
    // init-site note).
    let mut all_rows = crate::db::platform_pg_ident_rows();
    all_rows.append(&mut ident_rows);
    crate::db::write_pg_ident_rows(&all_rows).await?;
    Ok(())
}

/// VDC-6 (design/sentin8-vertical-data-plane-contract.md §VDC.6): copy the
/// platform registry rows into the vertical DB's `sys.vertical_services`
/// replica. Idempotent (upsert per row); enroll is the single writer — the
/// replica is read-only for services.
async fn replicate_registry_to_substrate(
    platform_pool: &sqlx::PgPool,
    vertical_pool: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let rows: Vec<(String, String, String, String, Option<serde_json::Value>)> = sqlx::query_as(
        r#"SELECT vertical, service_type, subdomain, health_path, admin_ui
             FROM sys.vertical_services"#,
    )
    .fetch_all(platform_pool)
    .await
    .map_err(|e| anyhow::anyhow!("registry replica read: {e}"))?;
    let row_count = rows.len();

    for (vertical, service_type, subdomain, health_path, admin_ui) in &rows {
        sqlx::query(
            r#"INSERT INTO sys.vertical_services
                   (vertical, service_type, subdomain, health_path, admin_ui)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (vertical, service_type) DO UPDATE
                 SET subdomain = EXCLUDED.subdomain,
                     health_path = EXCLUDED.health_path,
                     admin_ui = EXCLUDED.admin_ui"#,
        )
        .bind(vertical)
        .bind(service_type)
        .bind(subdomain)
        .bind(health_path)
        .bind(admin_ui)
        .execute(vertical_pool)
        .await
        .map_err(|e| anyhow::anyhow!("registry replica upsert {service_type}: {e}"))?;
    }
    println!("  Replicated {row_count} registry row(s) into the vertical substrate");
    Ok(())
}

/// Phase 28 (POLICY-CLI-1/2): upsert declarative Shield policy sets from the
/// registry into `policy_sets` (design/sentin8-policy-technical-design.md
/// §3.2). Runs during BOTH `vertical init` (seeds the bootstrap env) and
/// `vertical enroll` (re-upserts).
///
/// Semantics:
/// - Only entries whose `service` resolves (per-service entries inherit the
///   service's `service_type`; vertical-wide entries carry an explicit
///   `service`) are applied.
/// - Shield text is validated at enroll time (parse per statement; schema
///   validation when a schema is present) — an invalid policy FAILS the
///   enroll/init with a clear error (write-time gate, design §3.1).
/// - ON CONFLICT overwrite applies ONLY to `origin='platform'` rows;
///   `origin='tenant'` rows are NEVER touched (tenant authorship wins).
/// - Each applied upsert emits a `sentin8:sys:policy:updated` inbox event
///   (same transaction) so running services hot-reload.
async fn upsert_registry_policies(
    pool: &sqlx::PgPool,
    registry: &VerticalRegistry,
) -> anyhow::Result<()> {
    use sentin8::bus::outbox::PolicyUpdatedEnvelope;

    // Resolve the bootstrap env (system env): policy rows are env-scoped and
    // `vertical init`/`enroll` operate on the platform's system env
    // (SENTIN8_SYS_ENV_ID — the ops env of the sys org).
    let sys_env: Uuid = sqlx::query_scalar(
        r#"SELECT id FROM sys.environments WHERE id = '00000000-0000-0000-0000-000000000002'"#,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| anyhow::anyhow!("policy seed: bootstrap env lookup: {e}"))?
    .ok_or_else(|| {
        anyhow::anyhow!("policy seed: system environment row not found — run `make infra-up` first")
    })?;

    // Per-service entries inherit service_type; vertical-wide entries carry
    // an explicit `service`.
    let mut entries: Vec<(&RegistryPolicySet, String)> = Vec::new();
    for svc in &registry.services {
        for p in &svc.policies {
            entries.push((p, svc.service_type.clone()));
        }
    }
    for p in &registry.policies {
        if p.service.is_empty() {
            anyhow::bail!(
                "vertical-wide policy set '{}' must declare `service` (colon service_type)",
                p.policy_set_name
            );
        }
        entries.push((p, p.service.clone()));
    }

    if entries.is_empty() {
        return Ok(());
    }

    // Validate all entries first (fail the run before touching the DB) +
    // the enroll dry-run gate (§4.2) for enforced sets.
    for (entry, service) in &entries {
        sentin8::shield::validate_record_text(
            &entry.policy_set_name,
            &entry.policies,
            entry.schema.as_deref(),
        )
        .map_err(|e| {
            anyhow::anyhow!("policy set '{}' for {service}: {e}", entry.policy_set_name)
        })?;
        if entry.mode == "enforced" {
            sentin8::shield::runtime::dry_run_mirror(
                &entry.policies,
                &entry.policy_set_name,
                service,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "policy set '{}' for {service}: dry-run gate failed: {e}",
                    entry.policy_set_name
                )
            })?;
        }
    }

    let mut applied = 0usize;
    for (entry, service) in &entries {
        if !entry.default_enabled {
            continue;
        }
        let mut tx = pool.begin().await?;
        // RLS: run the upsert under platform context (system env) so the
        // insert passes `sentin8_context_initialized()`.
        sqlx::query(r#"SELECT sentin8_set_tenant_context($1, $2, $3, $4)"#)
            .bind(sys_env)
            .bind(String::new()) // subject_id: platform enroll path
            .bind("m2m".to_string()) // token type label for audit
            .bind("sys:admin".to_string()) // enroll operates as platform admin
            .execute(&mut *tx)
            .await?;
        let result: Option<(i32,)> = sqlx::query_as(
            r#"INSERT INTO sys.policy_sets
                   (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
               VALUES ($1, $2, $3, $4, $5, $6, 'platform', $7, 1, true)
               ON CONFLICT (env_id, service, policy_set_name) DO UPDATE
                   SET description = EXCLUDED.description,
                       policies    = EXCLUDED.policies,
                       schema      = EXCLUDED.schema,
                       mode        = EXCLUDED.mode,
                       version     = sys.policy_sets.version + 1,
                       enabled     = true,
                       updated_at  = now()
               WHERE sys.policy_sets.origin = 'platform'
               RETURNING version"#,
        )
        .bind(sys_env)
        .bind(service)
        .bind(&entry.policy_set_name)
        .bind(&entry.description)
        .bind(&entry.policies)
        .bind(&entry.schema)
        .bind(&entry.mode)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((version,)) = result {
            let envelope = PolicyUpdatedEnvelope {
                env_id: sys_env,
                service: service.clone(),
                policy_set_name: entry.policy_set_name.clone(),
                version: version as i64,
                enabled: true,
                mode: entry.mode.clone(),
            };
            sentin8::bus::outbox::insert_policy_event(&mut *tx, &envelope).await?;
            tx.commit().await?;
            applied += 1;
        } else {
            // Tenant-authored row with the same key — left untouched.
            tx.rollback().await?;
            println!(
                "    policy set '{}' for {service}: tenant-authored row kept (not overwritten)",
                entry.policy_set_name
            );
        }
    }
    println!("  Policy sets: {applied} platform row(s) upserted (tenant rows untouched)");
    Ok(())
}

/// Upsert the registry's ReBAC relation tuples into `policy_relations`
/// (Phase 28 §3.1c — POLICY-CLI-2). Same semantics as policy sets: rows are
/// env-scoped to the bootstrap (system) env, `origin='platform'` rows are
/// overwritten with the registry version, `origin='tenant'` rows are never
/// touched. The relation event envelope rides the same outbox helper.
async fn upsert_registry_relations(
    pool: &sqlx::PgPool,
    registry: &VerticalRegistry,
) -> anyhow::Result<()> {
    use sentin8::bus::outbox::PolicyUpdatedEnvelope;

    let sys_env: Uuid = sqlx::query_scalar(
        r#"SELECT id FROM sys.environments WHERE id = '00000000-0000-0000-0000-000000000002'"#,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| anyhow::anyhow!("relation seed: bootstrap env lookup: {e}"))?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "relation seed: system environment row not found - run `make infra-up` first"
        )
    })?;

    let mut entries: Vec<(&RegistryRelation, String)> = Vec::new();
    for svc in &registry.services {
        for r in &svc.relations {
            entries.push((r, svc.service_type.clone()));
        }
    }
    for r in &registry.relations {
        if r.service.is_empty() {
            anyhow::bail!(
                "vertical-wide relation tuple ({}/{}/{}) must declare `service` (colon service_type)",
                r.subject_type, r.relation, r.object_id
            );
        }
        entries.push((r, r.service.clone()));
    }

    if entries.is_empty() {
        return Ok(());
    }

    let mut applied = 0usize;
    for (entry, service) in &entries {
        let mut tx = pool.begin().await?;
        sqlx::query(r#"SELECT sentin8_set_tenant_context($1, $2, $3, $4)"#)
            .bind(sys_env)
            .bind(String::new())
            .bind("m2m".to_string())
            .bind("sys:admin".to_string())
            .execute(&mut *tx)
            .await?;
        let result: Option<(Uuid,)> = sqlx::query_as(
            r#"INSERT INTO sys.policy_relations
                   (env_id, service, subject_type, subject_id, relation, object_type, object_id, origin)
               VALUES ($1, $2, $3, $4, $5, $6, $7, 'platform')
               ON CONFLICT (env_id, subject_type, subject_id, relation, object_type, object_id) DO UPDATE
                   SET service = EXCLUDED.service
               WHERE sys.policy_relations.origin = 'platform'
               RETURNING id"#,
        )
        .bind(sys_env)
        .bind(service)
        .bind(&entry.subject_type)
        .bind(&entry.subject_id)
        .bind(&entry.relation)
        .bind(&entry.object_type)
        .bind(&entry.object_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((row_id,)) = result {
            let envelope = PolicyUpdatedEnvelope {
                env_id: sys_env,
                service: service.clone(),
                policy_set_name: format!(
                    "{}/{}/{}",
                    entry.subject_type, entry.relation, entry.object_id
                ),
                version: 1,
                enabled: true,
                mode: "enforced".to_string(),
            };
            sentin8::bus::outbox::insert_policy_change_event(
                &mut *tx,
                &envelope,
                "sentin8:sys:policy:relations:updated",
            )
            .await?;
            let _ = row_id;
            tx.commit().await?;
            applied += 1;
        } else {
            tx.rollback().await?;
            println!(
                "    relation tuple '{}/{}/{}' for {service}: tenant-authored row kept",
                entry.subject_type, entry.relation, entry.object_id
            );
        }
    }
    println!("  Relation tuples: {applied} platform row(s) upserted (tenant rows untouched)");
    Ok(())
}

/// Upsert declarative policy sets + relation tuples from a service's
/// `--print-registration --section=policies|relations` output (SELFREG):
/// each service declares its own default Shield sets and ReBAC graph. Same
/// semantics as the registry path — `origin='platform'` rows are overwritten,
/// `origin='tenant'` rows are never touched. Shield text is validated at
/// enroll time (invalid text fails the run before touching the DB).
pub(crate) async fn upsert_registration_policies(
    pool: &sqlx::PgPool,
    service: &str,
    policies: Option<&serde_json::Value>,
    relations: Option<&serde_json::Value>,
    substrate: bool,
) -> anyhow::Result<()> {
    use sentin8::bus::outbox::PolicyUpdatedEnvelope;

    // VDC-5 (design/sentin8-vertical-data-plane-contract.md §VDC.6): a
    // `substrate` copy seeds the SAME rows into a VERTICAL database's local
    // policy tables — the service's Shield engine boot-loads from its OWN
    // database. Two behavioral differences from the platform copy:
    //   • no `sys.environments` bootstrap-row check (the vertical DB has no
    //     platform tenant tables by design) — the system env UUID constant
    //     is used directly;
    //   • no outbox reload event (the platform copy, seeded in the same
    //     enroll/init pass, emits the single `policy:updated` event; every
    //     hot-reload consumer — platform or vertical — reloads from its
    //     OWN database on that event).
    let sys_env: Uuid = if substrate {
        sentin8::config::SYSTEM_ENV_ID
    } else {
        sqlx::query_scalar(
            r#"SELECT id FROM sys.environments WHERE id = '00000000-0000-0000-0000-000000000002'"#,
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow::anyhow!("policy seed: bootstrap env lookup: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "policy seed: system environment row not found — run `make infra-up` first"
            )
        })?
    };

    // ── Policy sets ──
    if let Some(set_array) = policies.and_then(|v| v.as_array()) {
        for entry in set_array {
            let name = entry
                .get("policy_set_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let text = entry.get("policies").and_then(|v| v.as_str()).unwrap_or("");
            let description = entry
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let schema = entry.get("schema").and_then(|v| v.as_str());
            let enabled = entry
                .get("default_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if name.is_empty() || text.is_empty() {
                continue;
            }
            sentin8::shield::validate_record_text(name, text, schema)
                .map_err(|e| anyhow::anyhow!("policy set '{name}' for {service}: {e}"))?;
            // Declared posture is honored verbatim (design §3.2 — the
            // registering binary is the source of truth; no hardcoded
            // shadow). Platform sets default to `enforced` (decision
            // 2026-09-07); the registration decl carries the mode explicitly.
            let declared_mode = entry
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("enforced");
            if declared_mode != "enforced" && declared_mode != "shadow" {
                anyhow::bail!(
                    "policy set '{name}' for {service}: invalid mode '{declared_mode}' (enforced|shadow)"
                );
            }
            let mut tx = pool.begin().await?;
            sqlx::query(r#"SELECT sentin8_set_tenant_context($1, $2, $3, $4)"#)
                .bind(sys_env)
                .bind(String::new())
                .bind("m2m".to_string())
                .bind("sys:admin".to_string())
                .execute(&mut *tx)
                .await?;
            let result: Option<(i32,)> = sqlx::query_as(
                r#"INSERT INTO sys.policy_sets
                       (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
                   VALUES ($1, $2, $3, $4, $5, $6, 'platform', $8, 1, $7)
                   ON CONFLICT (env_id, service, policy_set_name) DO UPDATE
                       SET description = EXCLUDED.description,
                           policies    = EXCLUDED.policies,
                           schema      = EXCLUDED.schema,
                           mode        = EXCLUDED.mode,
                           enabled     = EXCLUDED.enabled,
                           version     = sys.policy_sets.version + 1,
                           updated_at  = now()
                   WHERE sys.policy_sets.origin = 'platform'
                   RETURNING version"#,
            )
            .bind(sys_env)
            .bind(service)
            .bind(name)
            .bind(description)
            .bind(text)
            .bind(schema)
            .bind(enabled)
            .bind(declared_mode)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((version,)) = result {
                let envelope = PolicyUpdatedEnvelope {
                    env_id: sys_env,
                    service: service.to_string(),
                    policy_set_name: name.to_string(),
                    version: version as i64,
                    enabled,
                    mode: declared_mode.to_string(),
                };
                if !substrate {
                    sentin8::bus::outbox::insert_policy_event(&mut *tx, &envelope).await?;
                }
                tx.commit().await?;
                // Enroll-time dry-run gate (design §4.2): an ENFORCED set that
                // denies its own referenced actions would lock the service out
                // at the very next request. Verify each permit against a
                // synthetic principal holding exactly the scope each
                // `principal.scopes.contains("…")` references, evaluated for
                // that same action id. Failure fails the enroll with a clear
                // error (the set is still committed — mode flip is the
                // rollback lever, but the operator is warned loudly).
                if let Err(e) = sentin8::shield::runtime::dry_run_mirror(text, name, service) {
                    anyhow::bail!("policy set '{name}' for {service}: dry-run gate failed: {e}");
                }
                println!(
                    "    policy set '{name}' for {service} seeded (v{version}, {declared_mode})"
                );
            } else {
                tx.rollback().await?;
                println!("    policy set '{name}' for {service}: tenant-authored row kept");
            }
        }
    }

    // ── Relation tuples ──
    if let Some(rel_array) = relations.and_then(|v| v.as_array()) {
        for entry in rel_array {
            let subject_type = entry
                .get("subject_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let subject_id = entry
                .get("subject_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let relation = entry.get("relation").and_then(|v| v.as_str()).unwrap_or("");
            let object_type = entry
                .get("object_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let object_id = entry
                .get("object_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if subject_type.is_empty() || relation.is_empty() || object_type.is_empty() {
                anyhow::bail!(
                    "relation tuple for {service} is missing subject/relation/object fields"
                );
            }
            let mut tx = pool.begin().await?;
            sqlx::query(r#"SELECT sentin8_set_tenant_context($1, $2, $3, $4)"#)
                .bind(sys_env)
                .bind(String::new())
                .bind("m2m".to_string())
                .bind("sys:admin".to_string())
                .execute(&mut *tx)
                .await?;
            let result: Option<(Uuid,)> = sqlx::query_as(
                r#"INSERT INTO sys.policy_relations
                       (env_id, service, subject_type, subject_id, relation, object_type, object_id, origin)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, 'platform')
                   ON CONFLICT (env_id, subject_type, subject_id, relation, object_type, object_id) DO UPDATE
                       SET service = EXCLUDED.service
                   WHERE sys.policy_relations.origin = 'platform'
                   RETURNING id"#,
            )
            .bind(sys_env)
            .bind(service)
            .bind(subject_type)
            .bind(subject_id)
            .bind(relation)
            .bind(object_type)
            .bind(object_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((row_id,)) = result {
                let envelope = PolicyUpdatedEnvelope {
                    env_id: sys_env,
                    service: service.to_string(),
                    policy_set_name: format!("{subject_type}/{relation}/{object_id}"),
                    version: 1,
                    enabled: true,
                    mode: "enforced".to_string(),
                };
                if !substrate {
                    sentin8::bus::outbox::insert_policy_change_event(
                        &mut *tx,
                        &envelope,
                        "sentin8:sys:policy:relations:updated",
                    )
                    .await?;
                }
                let _ = row_id;
                tx.commit().await?;
                println!("    relation tuple '{subject_type}/{relation}/{object_id}' for {service} seeded");
            } else {
                tx.rollback().await?;
                println!("    relation tuple for {service}: tenant-authored row kept");
            }
        }
    }
    Ok(())
}

/// Try to merge catalog entries into captain's live catalog via HTTP API.
/// If captain isn't running, this is a no-op — captain will load the
/// catalog at startup from SENTIN8_CAPTAIN_CATALOG_PATHS.
async fn merge_into_captain(registry: &VerticalRegistry, registry_path: &str) {
    let vertical_root = std::path::Path::new(registry_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Build catalog entries with resolved absolute binary paths. Vertical-wide
    // `extra_env` (REG-9) is merged under each service's own map — the
    // per-service value wins on key conflict.
    let entries: Vec<serde_json::Value> = registry
        .services
        .iter()
        .filter_map(|svc| {
            let binary_rel = svc.binary.as_str();
            if binary_rel.is_empty() {
                return None;
            }
            let binary_abs = resolve_binary_path(binary_rel, &vertical_root)?;
            if !binary_abs.exists() {
                eprintln!(
                    "  WARNING: binary not found for {} — skipping catalog merge",
                    svc.service_type
                );
                return None;
            }
            let binary_name = binary_abs
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| svc.service_type.clone());
            let mut merged_env = registry.extra_env.clone();
            for (k, v) in &svc.extra_env {
                merged_env.insert(k.clone(), v.clone());
            }
            let mut entry = serde_json::json!({
                "service_type": svc.service_type,
                "binary": binary_name,
                "binary_path": binary_abs.to_string_lossy().to_string(),
                "start_priority": svc.start_priority,
                "upgrade_stop_first": svc.upgrade_stop_first,
                "extra_env": merged_env,
            });
            // Only the DECLARED fields overwrite captain's catalog defaults —
            // a registry JSON that does not mention probe mode / ports must
            // not flatten captain's per-service defaults (the proxy kill-loop
            // incident: a bare `sentin8:proxy` registry entry reset the
            // mgmt-port HTTP probe to the https://443 default, and captain
            // SIGKILLed the healthy proxy every ~55s).
            let obj = entry.as_object_mut().unwrap();
            if let Some(v) = svc.use_http_health {
                obj.insert("use_http_health".into(), serde_json::json!(v));
            }
            if let Some(v) = svc.fixed_port {
                obj.insert("fixed_port".into(), serde_json::json!(v));
            }
            if let Some(v) = svc.health_port {
                obj.insert("health_port".into(), serde_json::json!(v));
            }
            // Spawn-completeness: the STATIC catalog file
            // (`{vertical}/services/catalog.json`) declares per-service
            // `database_env_vars` — the DSN env-var names captain propagates
            // from ITS environment at spawn (VDC §VDC.3, catalog.rs spawn
            // branches). The registry JSON has no such field, so a merged
            // entry without it spawned with an EMPTY propagation list: any
            // vertical start issued while captain was already running
            // (post-enroll restart) ran the binary with no `{V}_*_DATABASE_URL`
            // and the VDC-3 fail-fast panicked ("points at database 'sentin8'
            // but owns 'bank8'"). Join the static file's declaration here so
            // the merged entry is spawn-complete regardless of which path
            // installed it.
            let catalog_file = vertical_root.join("services/catalog.json");
            if let Ok(raw) = std::fs::read_to_string(&catalog_file) {
                if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&raw) {
                    for c in &list {
                        if c.get("service_type").and_then(|v| v.as_str())
                            == Some(svc.service_type.as_str())
                        {
                            if let Some(vars) =
                                c.get("database_env_vars").and_then(|v| v.as_array())
                            {
                                obj.insert("database_env_vars".into(), serde_json::json!(vars));
                            }
                            break;
                        }
                    }
                }
            }
            Some(entry)
        })
        .collect();

    if entries.is_empty() {
        return;
    }

    // Try to call captain's merge-catalog API. Transport resolution mirrors
    // the `captain` commands (DEVUI-2): prefer the local UDS control socket
    // (peer-credential auth — no bearer token required) and fall back to
    // TCP + operator token. The TCP path is fragile here: the token is
    // attached best-effort, and after an Auth restart (JWKS rotation) the
    // cached token 401s — enroll then SILENTLY skips the merge, captain's
    // runtime catalog loses the vertical, and every subsequent `captain
    // start <service>` fails with 'not in catalog' (incident 2026-09-09:
    // bank8 enroll ran green but merge-catalog returned 401, `make start`
    // skipped all 4 services).
    let (status, body): (reqwest::StatusCode, bytes::Bytes) =
        match crate::transport::CaptainTransport::resolve() {
            crate::transport::CaptainTransport::Unix { socket_path } => {
                let client = crate::transport::UdsClient::new(socket_path);
                match client
                    .request(
                        hyper::Method::POST,
                        "/v1/captain/merge-catalog",
                        Some(serde_json::json!({"entries": entries})),
                    )
                    .await
                {
                    Ok((st, b)) => (
                        reqwest::StatusCode::from_u16(st.as_u16())
                            .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                        b,
                    ),
                    Err(_) => return, // captain not reachable — catalog loads at startup
                }
            }
            crate::transport::CaptainTransport::Tcp => {
                let captain_url = crate::config::captain_url();
                let http = match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let url = format!(
                    "{}/v1/captain/merge-catalog",
                    captain_url.trim_end_matches('/')
                );
                // merge-catalog is Shield-gated on `sentin8:captain:admin`
                // (design §6.1.1 — it inserts executable binary paths).
                // Attach the operator's cached token best-effort; a
                // rejection lands in the catch-all arm below, and captain
                // picks up the vertical catalog from
                // SENTIN8_CAPTAIN_CATALOG_PATHS on next restart.
                let mut req = http
                    .post(&url)
                    .json(&serde_json::json!({"entries": entries}));
                if let Ok(token) = crate::auth::get_valid_token().await {
                    req = req.bearer_auth(&token);
                }
                match req.send().await {
                    Ok(resp) => {
                        let st = resp.status();
                        match resp.bytes().await {
                            Ok(b) => (st, b),
                            Err(_) => return,
                        }
                    }
                    Err(_) => return, // captain not running — catalog loads at startup
                }
            }
        };
    if status.is_success() {
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let merged = body
            .get("merged_services")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        println!("  Merged {merged} services into captain catalog");
    } else if status.as_u16() == 401 {
        // Stale/absent operator token on the TCP path — surface it instead
        // of silently swallowing (the enroll summary looked green while the
        // catalog never landed; see incident note above).
        eprintln!(
            "  WARNING: merge-catalog rejected (401) — operator token stale; run `sentin8-cli signin` and re-enroll, or set SENTIN8_CAPTAIN_CATALOG_PATHS for the next captain restart"
        );
    }
}

/// Scan `apps/*/app.json` files in the vertical root directory and register
/// each app (SELFREG-10). This replaces the `apps[]` array in the registry
/// JSON — each app folder has its own `app.json` with listing metadata.
async fn register_apps_from_dir(
    registry_path: &str,
    registry_apps: &[RegistryApp],
    _apps_dir_name: &str,
    valkey_conn: &glide::GlideClient,
    pool: &sqlx::PgPool,
) -> anyhow::Result<usize> {
    let vertical_root = std::path::Path::new(registry_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // System env UUID — the platform owner for auto-registered apps.
    let sys_env_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);
    let system_user_sub = "system";

    // Ensure the table exists.
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
            visibility      TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('usr', 'env', 'public')),
            env_id          UUID,
            roles           JSONB NOT NULL DEFAULT '[]',
            default_signup_role TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );"#,
    )
    .execute(pool)
    .await?;

    let mut count = 0;

    for reg_app in registry_apps {
        // TWO forms (WARN-11): inline (path empty → slug/web_dir/listing
        // ride the fragment fields) or pointer (path → external app.json).
        // Both reduce to the same four values: slug, web_dir, listing,
        // app_dir (for the web-root join).
        let (app, app_dir): (serde_json::Value, std::path::PathBuf) = if reg_app.path.is_empty() {
            // Inline form: the app_dir is the SOURCE REPO dir (stamped
            // at fragment load — the merged registry lives in /tmp, so
            // its parent is meaningless).
            let app_dir = if reg_app.source_dir.is_empty() {
                std::path::Path::new(registry_path)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
            } else {
                std::path::PathBuf::from(&reg_app.source_dir)
            };
            (
                serde_json::json!({
                    "slug": reg_app.slug,
                    "web_dir": reg_app.web_dir,
                    "listing": reg_app.listing,
                }),
                app_dir,
            )
        } else {
            let app_json_path = vertical_root.join(&reg_app.path);
            if !app_json_path.exists() {
                println!(
                    "    app: {} — {} not found, skipping",
                    reg_app.slug,
                    app_json_path.display()
                );
                continue;
            }
            let json_str = std::fs::read_to_string(&app_json_path)
                .map_err(|e| anyhow::anyhow!("read {}: {e}", app_json_path.display()))?;
            let app: serde_json::Value = serde_json::from_str(&json_str)
                .map_err(|e| anyhow::anyhow!("parse {}: {e}", app_json_path.display()))?;
            let app_dir = app_json_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| vertical_root.to_path_buf());
            (app, app_dir)
        };

        let slug = app
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or(&reg_app.slug);
        let web_dir = app
            .get("web_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("build/web");
        let listing = app.get("listing").cloned().unwrap_or(serde_json::json!({}));

        let app_name = listing
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or(slug);
        let app_slug = listing
            .get("app_slug")
            .and_then(|v| v.as_str())
            .unwrap_or(slug);
        let description = listing.get("description").and_then(|v| v.as_str());
        let backend_url = listing
            .get("backend_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let supports_dcr = listing
            .get("supports_dcr")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let visibility = listing
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("public");
        let status = listing
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("published");
        let oauth_defaults = listing
            .get("oauth_defaults")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let roles = listing
            .get("roles")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        let default_signup_role = listing
            .get("default_signup_role")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // APP-4: a listing row is a (slug, channel) release; the
        // manifest may pin `version` and `channel` (defaults 0.0.0/stable).
        let version = listing
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let channel = listing
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("stable");
        sqlx::query(
            r#"INSERT INTO app.store_listings
                  (app_name, app_slug, description, backend_url, supports_dcr,
                   oauth_defaults, created_by, usr_id, visibility, env_id,
                   status, roles, default_signup_role, version, channel)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14)
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
                   updated_at = now()"#,
        )
        .bind(app_name)
        .bind(app_slug)
        .bind(description)
        .bind(backend_url)
        .bind(supports_dcr)
        .bind(&oauth_defaults)
        .bind(system_user_sub)
        .bind(visibility)
        .bind(sys_env_id)
        .bind(status)
        .bind(&roles)
        .bind(default_signup_role)
        .bind(version)
        .bind(channel)
        .execute(pool)
        .await?;

        // The web root MUST be ABSOLUTE: the web server resolves the key's
        // value against ITS own cwd (which differs from the CLI's at enroll
        // time — a relative fallback silently pointed at a dead path). When
        // the build dir doesn't exist yet (app not built), canonicalize
        // fails — anchor the fallback on the source repo's absolute path.
        let app_dir_abs = if app_dir.is_absolute() {
            app_dir
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(&app_dir)
        };
        // Lexically collapse `..` chains (`sentin8-cli/../../bank8/…` →
        // the real absolute): the stored key must be unambiguous to any
        // consumer regardless of ITS cwd. Pure text normalization (no FS
        // access) — safe on a not-yet-built dir.
        let app_dir_abs = {
            let mut clean = std::path::PathBuf::new();
            for comp in app_dir_abs.components() {
                match comp {
                    std::path::Component::ParentDir => {
                        clean.pop();
                    }
                    c => clean.push(c.as_os_str()),
                }
            }
            clean
        };
        let web_root = app_dir_abs
            .join(web_dir)
            .canonicalize()
            .unwrap_or_else(|_| app_dir_abs.join(web_dir));
        let key = format!("captain:app_dir:{app_slug}");
        valkey_conn
            .custom_command(&["SET", &key, web_root.to_string_lossy().as_ref()])
            .await
            .map_err(|e| anyhow::anyhow!("SET app dir: {e}"))?;
        if slug != app_slug {
            let short_key = format!("captain:app_dir:{slug}");
            valkey_conn
                .custom_command(&["SET", &short_key, web_root.to_string_lossy().as_ref()])
                .await
                .map_err(|e| anyhow::anyhow!("SET app dir: {e}"))?;
        }
        println!("    app: {app_slug} → {}", web_root.display());
        count += 1;
    }

    Ok(count)
}

/// Run a service binary with `--print-registration --section=<section>` and
/// return the parsed JSON output (SELFREG-8/9). Returns None if the binary
/// doesn't exist or doesn't support `--print-registration` (timeout or
/// non-JSON output — a worker that started a server instead). A non-zero
/// exit is a HARD error (operator decision 2026-09-10, REG-15): a binary
/// that crashes under the flag is a broken service definition — enroll must
/// fail loudly, not silently degrade to the registry-JSON fallback. Every
/// service that appears in a registry must carry its own
/// `--print-registration` handler (captain included — REG-15).
///
/// `binary_path` may be a bare name (e.g. `sentin8-auth`) or a relative path
/// (e.g. `target/release/sentin8-auth`). Bare names are resolved against
/// `target/release` under `vertical_root`, or against
/// `SENTIN8_CAPTAIN_BINARY_PREFIX` (colon-separated dirs) if set.
async fn run_print_registration(
    binary_path: &str,
    section: &str,
    vertical_root: &std::path::Path,
) -> anyhow::Result<Option<serde_json::Value>> {
    // Resolve the binary: if it's already a path that exists, use it directly.
    // Otherwise, try bare-name resolution against target/release and the prefix.
    let abs_path = resolve_binary_path(binary_path, vertical_root);
    let abs_path = match abs_path {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    // Use a timeout — some binaries (e.g. workers) may not support
    // --print-registration and will start the server instead of exiting.
    // The child inherits the CLI's env, which dotenvy populated — the
    // `{SERVICE}_PORT` vars it requires are only in .env (incident
    // 2026-09-22: without them the probe panicked → stderr → JSON check
    // failed → every service fell back to the legacy registry JSON and
    // skipped self-description entirely).
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(&abs_path)
            .arg("--print-registration")
            .arg(format!("--section={section}"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await;

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!(
                "run {binary_path} --print-registration: {e}"
            ))
        }
        Err(_) => {
            // Timed out — binary doesn't support --print-registration (started server instead).
            eprintln!("  WARNING: {binary_path} did not respond to --print-registration within 5s — skipping");
            return Ok(None);
        }
    };

    if !output.status.success() {
        // Strict probe (REG-15 decision — no fallback): a non-zero exit means
        // the service is BROKEN under the flag (e.g. its main() initializes
        // config before honoring the flag and panicked on missing env). Fail
        // the enroll loudly — a service that appears in a registry must
        // self-describe.
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "{binary_path} --print-registration failed: {stderr}"
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(None);
    }

    // Verify the output is valid JSON (not log lines from a server that
    // ignored the flag).
    let json: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "  WARNING: {binary_path} --print-registration output is not valid JSON — skipping"
            );
            return Ok(None);
        }
    };

    Ok(Some(json))
}

/// Resolve a binary name/path to an absolute path.
///
/// - If `binary` contains a path separator or is already absolute, join it
///   to `vertical_root` (legacy `target/release/sentin8-auth` style).
/// - Otherwise (bare name like `sentin8-auth`), try:
///   1. `SENTIN8_CAPTAIN_BINARY_PREFIX` dirs (colon-separated, e.g. `/usr/bin`).
///   2. `vertical_root/target/release/<binary>` (dev build output).
///   3. `vertical_root/<binary>` (last resort).
fn resolve_binary_path(
    binary: &str,
    vertical_root: &std::path::Path,
) -> Option<std::path::PathBuf> {
    // If it looks like a path (contains `/` or is absolute), join to vertical_root.
    if binary.contains('/') || binary.starts_with('.') {
        return Some(vertical_root.join(binary));
    }

    // Bare name — try SENTIN8_CAPTAIN_BINARY_PREFIX dirs.
    if let Ok(prefixes) = std::env::var("SENTIN8_CAPTAIN_BINARY_PREFIX") {
        for dir in prefixes.split(':') {
            let candidate = std::path::Path::new(dir).join(binary);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // Fall back to target/release under the vertical root (dev build output).
    let dev_path = vertical_root.join("target/release").join(binary);
    if dev_path.is_file() {
        return Some(dev_path);
    }

    // Last resort: vertical_root/<binary>.
    Some(vertical_root.join(binary))
}

/// Provision the Valkey certificate-identity plane (group DESIGN.md §3.1).
///
/// The TLS listener maps each client cert's CN to the ACL user of the same
/// name — NO Valkey secrets exist. This pass creates, for every workload
/// this service declares (`m2m_grants`): an ACL user `m2m-{workload}` with
/// MemBus data-plane key patterns and the RESP command allowlist every
/// service needs, plus READ on the authorization map and the captain
/// registry. Declarative — the workload list comes from the service's own
/// `--print-registration --section=m2m_grants` output; this binary contains
/// no vertical-specific knowledge.
///
/// Idempotent: re-enrolling refreshes patterns/commands; the users are
/// secret-free (the certificate IS the credential), so nothing can desync.
/// Derive a workload's OWN Valkey key-namespace prefix from its name —
/// the namespace its handlers write (`auth:*`, `bff:*`, `bus:*`, …).
///
/// Colon identities carry the namespace in the SECOND segment
/// (`sentin8:auth` → `auth`, `sentin8:auth-policy` → `auth` — the
/// dash-suffixed sibling shares the parent service's namespace, the
/// same convention the services' key literals use). Dash identities
/// use their FIRST segment (`captain-remote` → `captain`).
fn workload_namespace(workload: &str) -> String {
    if let Some((_vertical, rest)) = workload.split_once(':') {
        // `auth-policy` → `auth`; a bare `auth` stays `auth`.
        rest.split('-').next().unwrap_or(rest).to_string()
    } else {
        workload.split('-').next().unwrap_or(workload).to_string()
    }
}

async fn provision_workload_acl_users(
    workloads: &[String],
    extra_key_patterns: &[String],
    extra_commands: &[String],
    valkey_conn: &glide::GlideClient,
) -> anyhow::Result<()> {
    for workload in workloads {
        // The MemBus data plane + registry-map read + captain-registry
        // read are the platform-wide baseline every service holds; a
        // vertical's `valkey` fragment section may extend the key
        // patterns (its own namespaces) and the command allowlist.
        // The workload's OWN key namespace derives from its name: a
        // colon identity (`sentin8:auth` → `~auth:*`,
        // `sentin8:auth-policy` → `~auth:*` too — the policy worker
        // shares its parent service's namespace) and a dash identity
        // (`captain-remote` → `~captain:*`) maps its first segment.
        // This is the same convention the services' own code uses for
        // their key prefixes — no vertical-specific knowledge here.
        let key_ns = workload_namespace(workload);
        let mut args: Vec<String> = vec![
            "ACL".into(),
            "SETUSER".into(),
            format!("m2m-{workload}"),
            "on".into(),
            "resetkeys".into(),
            format!("~{key_ns}:*"),
            "~mbus:*".into(),
            "~mchan:*".into(),
            "~m2m:workloads".into(),
            "~m2m:declared".into(),
            "~captain:*".into(),
            "~stat:metrics:*".into(),
            "~bus:*".into(),
            "~bus:dlq:*".into(),
            "~bus:delayed:*".into(),
            "~traffic:*".into(),
            "~error_metrics:*".into(),
            "~membus:*".into(),
            // Pub/sub channels (Valkey 9 ACL2): the pub/sub data plane —
            // MemBus `mchan:*` families, captain registry notifications,
            // stat metric channels, and the traffic/error metrics
            // publishers. Without channel patterns, `resetchannels`
            // denies every SUBSCRIBE.
            "&mbus:*".into(),
            "&mchan:*".into(),
            "&captain:*".into(),
            "&stat:*".into(),
            "&bus:*".into(),
            "&traffic:*".into(),
            "&error_metrics:*".into(),
        ];
        for pattern in extra_key_patterns {
            args.push(format!("~{pattern}"));
        }
        // Commands: deny all categories, then allow the RESP surface the
        // platform's Valkey clients actually issue (SDK membus, Bus core
        // streams, captain registry, session stores, metrics publishers)
        // — including GLIDE's connect-time probes (`INFO`, `CLIENT`):
        // valkey-glide issues them on every connection handshake, so
        // every workload user MUST carry them or the client cannot
        // connect at all (group DESIGN.md §3.1).
        args.extend([
            "-@all".into(),
            "+ping".into(),
            "+info".into(),
            "+client".into(),
            "+dbsize".into(),
            "+command".into(),
            "+get".into(),
            "+set".into(),
            "+setex".into(),
            "+setnx".into(),
            "+getdel".into(),
            "+del".into(),
            "+expire".into(),
            "+pexpire".into(),
            "+ttl".into(),
            "+pttl".into(),
            "+incr".into(),
            "+incrby".into(),
            "+type".into(),
            "+exists".into(),
            "+scan".into(),
            "+keys".into(),
            "+hset".into(),
            "+hget".into(),
            "+hdel".into(),
            "+hgetall".into(),
            "+sadd".into(),
            "+srem".into(),
            "+smembers".into(),
            "+zadd".into(),
            "+zrem".into(),
            "+zrange".into(),
            "+zrangebyscore".into(),
            "+zcount".into(),
            "+lrange".into(),
            "+lrem".into(),
            "+rpush".into(),
            "+publish".into(),
            "+subscribe".into(),
            "+unsubscribe".into(),
            "+psubscribe".into(),
            "+punsubscribe".into(),
            "+ssubscribe".into(),
            "+sunsubscribe".into(),
            "+xadd".into(),
            "+xack".into(),
            "+xgroup".into(),
            "+xreadgroup".into(),
            "+xautoclaim".into(),
            "+xinfo".into(),
            "+xlen".into(),
            "+xpending".into(),
        ]);
        for command in extra_commands {
            args.push(format!("+{command}"));
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        valkey_conn
            .custom_command(&refs)
            .await
            .map_err(|e| anyhow::anyhow!("ACL SETUSER m2m-{workload}: {e}"))?;
    }
    if !workloads.is_empty() {
        println!(
            "  Valkey ACL: {} workload user(s) provisioned (certificate identity, no secrets)",
            workloads.len()
        );
    }
    Ok(())
}

/// Provision the plane's FIXED identities (group DESIGN.md §3.1):
///
/// - `m2m-valkey-control` — the local control path (compose healthcheck,
///   dev tooling): read-only infra keys, no write rights anywhere.
/// - `m2m-valkey-admin` — the operator's enroll identity: the only user
///   with `+acl` (user provisioning), scoped to Valkey administration.
/// - `m2m-valkey-registry-writer` — the ONLY user with write rights on
///   `m2m:workloads`/`m2m:declared`: the token-free authorization record
///   is not writable by any service; the CLI's map publishes present it.
/// - `default` — stripped of every right: the cert-CN mapping falls back
///   to it for unknown certs, so it must be inert (no commands, no keys).
///
/// Idempotent — the pass runs at every enroll and converges the state.
async fn provision_valkey_admin_users(valkey_conn: &glide::GlideClient) -> anyhow::Result<()> {
    // Local control: read-only infra keys.
    valkey_conn
        .custom_command(&[
            "ACL",
            "SETUSER",
            "m2m-valkey-control",
            "on",
            "resetkeys",
            "~captain:*",
            "~stat:metrics:*",
            "-@all",
            "+ping",
            "+info",
            "+client",
            "+dbsize",
            "+command",
            "+get",
            "+hget",
            "+hgetall",
            "+lrange",
            "+smembers",
            "+xlen",
        ])
        .await
        .map_err(|e| anyhow::anyhow!("ACL SETUSER m2m-valkey-control: {e}"))?;

    // Operator admin: Valkey administration + the control-plane writes
    // enroll performs (known-verticals set, service-registry cleanup).
    // NOT a `m2m:*` writer — that right belongs to the registry-writer
    // identity alone (group DESIGN.md §3.1).
    valkey_conn
        .custom_command(&[
            "ACL",
            "SETUSER",
            "m2m-valkey-admin",
            "on",
            "resetkeys",
            "~*",
            "-@all",
            "+acl",
            "+ping",
            "+info",
            "+config",
            "+client",
            "+dbsize",
            "+keys",
            "+scan",
            "+flushdb",
            "+flushall",
            "+del",
            "+sadd",
            "+srem",
            "+hgetall",
            "+hget",
            "+set",
            "+setex",
            "+get",
        ])
        .await
        .map_err(|e| anyhow::anyhow!("ACL SETUSER m2m-valkey-admin: {e}"))?;

    // Registry writer: the sole `m2m:*` write surface.
    valkey_conn
        .custom_command(&[
            "ACL",
            "SETUSER",
            "m2m-valkey-registry-writer",
            "on",
            "resetkeys",
            "~m2m:workloads",
            "~m2m:declared",
            "-@all",
            "+ping",
            "+info",
            "+client",
            "+dbsize",
            "+command",
            "+hgetall",
            "+hget",
            "+hset",
            "+hdel",
            "+sadd",
            "+srem",
            "+smembers",
        ])
        .await
        .map_err(|e| anyhow::anyhow!("ACL SETUSER m2m-valkey-registry-writer: {e}"))?;

    // The default user: unknown-cert connections land here — inert. The
    // captain registry + MemBus writes all present named identities.
    valkey_conn
        .custom_command(&[
            "ACL",
            "SETUSER",
            "default",
            "off",
            "resetkeys",
            "-@all",
            "resetpass",
        ])
        .await
        .map_err(|e| anyhow::anyhow!("ACL SETUSER default: {e}"))?;

    println!(
        "  Valkey ACL: control/admin/registry-writer users provisioned; default user disabled"
    );
    Ok(())
}

/// Run a GLIDE command and decode a `Vec<String>` reply
/// (best-effort: an error or unexpected shape yields an empty vector —
/// the callers are cleanup scans).
async fn valkey_cmd_strings(client: &glide::GlideClient, name: &str, args: &[&str]) -> Vec<String> {
    let mut argv: Vec<&str> = vec![name];
    argv.extend_from_slice(args);
    match client.custom_command(&argv).await {
        Ok(glide::ValkeyValue::Array(items)) => items
            .into_iter()
            .filter_map(|v| match v {
                glide::ValkeyValue::BulkString(b) => Some(String::from_utf8_lossy(&b).into_owned()),
                glide::ValkeyValue::SimpleString(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) async fn open_admin_valkey_conn(valkey_url: &str) -> anyhow::Result<glide::GlideClient> {
    sentin8::middleware::valkey_client(valkey_url, "valkey-admin")
        .await
        .map_err(|e| anyhow::anyhow!("admin Valkey connection: {e} — run `make infra-tls` first"))
}

/// Apply SQL migrations from `--print-registration --section=sql` output
/// (SELFREG-9). Uses a `sys.vertical_migrations` table to track applied
/// migrations and only applies new ones (idempotent).
async fn apply_sql_migrations(
    pool: &sqlx::PgPool,
    vertical: &str,
    service_type: &str,
    migrations: &serde_json::Value,
    sentin8_domain: &str,
) -> anyhow::Result<usize> {
    // Create the migrations tracking table.
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.vertical_migrations (
            vertical      TEXT NOT NULL,
            service_type  TEXT NOT NULL,
            version       INT NOT NULL,
            name          TEXT NOT NULL,
            applied_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (vertical, service_type, version)
        )"#,
    )
    .execute(pool)
    .await?;

    let domain_literal = format!("'{}'", sentin8_domain);
    let empty_migrations: Vec<serde_json::Value> = vec![];
    let migrations_arr = migrations.as_array().unwrap_or(&empty_migrations);
    let mut applied = 0;

    for m in migrations_arr {
        let version = m.get("version").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let sql = m.get("sql").and_then(|v| v.as_str()).unwrap_or("");

        // Check if already applied.
        let already = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM sys.vertical_migrations
               WHERE vertical = $1 AND service_type = $2 AND version = $3"#,
        )
        .bind(vertical)
        .bind(service_type)
        .bind(version)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        if already > 0 {
            continue;
        }

        // Apply the SQL with domain substitution.
        let sql = sql
            .replace(":'sentin8_domain'", &domain_literal)
            .replace(":'sentin8.domain'", &domain_literal);
        println!("    applying {service_type} migration {version} ({name})...");
        let mut conn = pool.acquire().await?;
        sqlx::raw_sql(&sql)
            .execute(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!("apply {service_type} migration {version}: {e}"))?;
        drop(conn);

        // Record the migration.
        sqlx::query(
            r#"INSERT INTO sys.vertical_migrations (vertical, service_type, version, name)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(vertical)
        .bind(service_type)
        .bind(version)
        .bind(name)
        .execute(pool)
        .await?;

        applied += 1;
    }

    Ok(applied)
}

/// Register a service from `--print-registration` output (SELFREG-8).
/// Called for each service binary that supports `--print-registration`.
// The registration aggregate carries every optional section as its own
// parameter — the natural arity of a self-describing record.
#[allow(clippy::too_many_arguments)]
async fn register_service_from_registration(
    pool: &sqlx::PgPool,
    vertical: &str,
    service_json: &serde_json::Value,
    admin_ui_json: Option<&serde_json::Value>,
    admin_scopes_json: Option<&serde_json::Value>,
    error_codes_json: Option<&serde_json::Value>,
    consent_json: Option<&serde_json::Value>,
    audit_findings_json: Option<&serde_json::Value>,
    service_actions_json: Option<&serde_json::Value>,
    m2m_grants_json: Option<&serde_json::Value>,
    openapi_json: Option<&serde_json::Value>,
    valkey_acl: Option<&RegistryValkeyAcl>,
    valkey_conn: &glide::GlideClient,
) -> anyhow::Result<()> {
    let service_type = service_json
        .get("service_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing service_type in registration output"))?;
    let subdomain = service_json
        .get("subdomain")
        .and_then(|v| v.as_str())
        .unwrap_or(service_type);
    let health_path = service_json
        .get("health_path")
        .and_then(|v| v.as_str())
        .unwrap_or("/v1/health");

    // Upsert into sentin8_vertical_services.
    sqlx::query(
        r#"INSERT INTO sys.vertical_services (vertical, service_type, subdomain, health_path, admin_ui)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (vertical, service_type) DO UPDATE
             SET subdomain = EXCLUDED.subdomain,
                 health_path = EXCLUDED.health_path,
                 admin_ui = EXCLUDED.admin_ui"#,
    )
    .bind(vertical)
    .bind(service_type)
    .bind(subdomain)
    .bind(health_path)
    .bind(admin_ui_json)
    .execute(pool)
    .await?;

    // Upsert admin scopes.
    //
    // `AdminScope` is `#[serde(untagged)]` — platform services emit the
    // tuple style (`["sentin8:post:admin", "sentin8:post:admin"]`) and verticals the typed
    // style (`{"role": ..., "scope": ...}`). Handle both: an object entry
    // reads `role`/`scope`; a 2-element array entry reads index 0/1.
    // Entries that yield an empty role or scope (unknown shape) are skipped
    // rather than inserted as empty rows (they would poison the registry —
    // the e2e post:write 403 incident, 2026-09-06).
    if let Some(scopes) = admin_scopes_json.and_then(|v| v.as_array()) {
        sqlx::query(
            "DELETE FROM sys.vertical_admin_scopes WHERE vertical = $1 AND service_type = $2",
        )
        .bind(vertical)
        .bind(service_type)
        .execute(pool)
        .await?;
        for scope in scopes {
            let (role, scope_val) = if let (Some(r), Some(s)) = (
                scope.get("role").and_then(|v| v.as_str()),
                scope.get("scope").and_then(|v| v.as_str()),
            ) {
                (r, s)
            } else if let Some(pair) = scope.as_array() {
                if pair.len() == 2 {
                    match (pair[0].as_str(), pair[1].as_str()) {
                        (Some(r), Some(s)) => (r, s),
                        _ => continue,
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            };
            if role.is_empty() || scope_val.is_empty() {
                continue;
            }
            sqlx::query(
                r#"INSERT INTO sys.vertical_admin_scopes (vertical, service_type, role, scope)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (vertical, service_type, role, scope) DO NOTHING"#,
            )
            .bind(vertical)
            .bind(service_type)
            .bind(role)
            .bind(scope_val)
            .execute(pool)
            .await?;
        }
    }

    // Upsert error codes.
    if let Some(errors) = error_codes_json.and_then(|v| v.as_array()) {
        for ec in errors {
            let enum_name = ec
                .get("enum")
                .or_else(|| ec.get("r#enum"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let code = ec.get("code").and_then(|v| v.as_str()).unwrap_or("");
            let status_code = ec
                .get("status_code")
                .and_then(|v| v.as_i64())
                .unwrap_or(500) as i32;
            sqlx::query(
                r#"INSERT INTO sys.vertical_error_codes (vertical, enum_name, error_code, status_code)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (vertical, enum_name) DO UPDATE
                     SET error_code = EXCLUDED.error_code, status_code = EXCLUDED.status_code"#,
            )
            .bind(vertical)
            .bind(enum_name)
            .bind(code)
            .bind(status_code)
            .execute(pool)
            .await?;
        }
    }

    // Upsert consent providers + flows.
    if let Some(consent) = consent_json {
        if let Some(providers) = consent.get("consent_providers").and_then(|v| v.as_array()) {
            for cp in providers {
                let feature = cp.get("feature").and_then(|v| v.as_str()).unwrap_or("");
                let data_type = cp.get("data_type").and_then(|v| v.as_str()).unwrap_or("");
                let cp_service = cp
                    .get("service_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or(service_type);
                let platform_domain_key = cp
                    .get("platform_domain_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let endpoint = cp.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
                let scope = cp.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                let response_key = cp
                    .get("response_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                sqlx::query(
                    r#"INSERT INTO sys.consent_providers (vertical, feature, data_type, service_type, platform_domain_key, endpoint, scope, response_key)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                       ON CONFLICT (feature, data_type, vertical) DO UPDATE
                         SET service_type = EXCLUDED.service_type,
                             platform_domain_key = EXCLUDED.platform_domain_key,
                             endpoint = EXCLUDED.endpoint,
                             scope = EXCLUDED.scope,
                             response_key = EXCLUDED.response_key"#,
                )
                .bind(vertical)
                .bind(feature)
                .bind(data_type)
                .bind(cp_service)
                .bind(platform_domain_key)
                .bind(endpoint)
                .bind(scope)
                .bind(response_key)
                .execute(pool)
                .await?;
            }
        }

        if let Some(flows) = consent.get("consent_flows").and_then(|v| v.as_array()) {
            for cf in flows {
                let flow_id = cf.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let trigger_patterns = cf
                    .get("trigger_patterns")
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                let cf_service = cf
                    .get("service_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or(service_type);
                let ui_endpoint = cf.get("ui_endpoint").and_then(|v| v.as_str()).unwrap_or("");
                let approve_endpoint = cf
                    .get("approve_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let deny_endpoint = cf
                    .get("deny_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                sqlx::query(
                    r#"INSERT INTO sys.consent_flows (vertical, flow_id, trigger_patterns, service_type, ui_endpoint, approve_endpoint, deny_endpoint)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)
                       ON CONFLICT (vertical, flow_id) DO UPDATE
                         SET trigger_patterns = EXCLUDED.trigger_patterns,
                             service_type = EXCLUDED.service_type,
                             ui_endpoint = EXCLUDED.ui_endpoint,
                             approve_endpoint = EXCLUDED.approve_endpoint,
                             deny_endpoint = EXCLUDED.deny_endpoint"#,
                )
                .bind(vertical)
                .bind(flow_id)
                .bind(&trigger_patterns)
                .bind(cf_service)
                .bind(ui_endpoint)
                .bind(approve_endpoint)
                .bind(deny_endpoint)
                .execute(pool)
                .await?;
            }
        }
    }

    // Upsert audit findings (SELFREG-16).
    if let Some(findings) = audit_findings_json.and_then(|v| v.as_array()) {
        // Clear old findings for this vertical (idempotent re-registration).
        sqlx::query("DELETE FROM sys.vertical_audit_findings WHERE vertical = $1")
            .bind(vertical)
            .execute(pool)
            .await?;
        for af in findings {
            let finding = af.get("finding").and_then(|v| v.as_str()).unwrap_or("");
            let recommendation = af
                .get("recommendation")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            sqlx::query(
                r#"INSERT INTO sys.vertical_audit_findings (vertical, finding, recommendation)
                   VALUES ($1, $2, $3)"#,
            )
            .bind(vertical)
            .bind(finding)
            .bind(recommendation)
            .execute(pool)
            .await?;
        }
        if !findings.is_empty() {
            println!("    Registered {} audit findings", findings.len());
        }
    }

    // Upsert service actions (SELFREG-17).
    if let Some(actions) = service_actions_json.and_then(|v| v.as_array()) {
        // Clear THIS service's old actions (idempotent re-registration).
        // DELETE must be scoped by service_type — not just vertical — or a
        // later service with an empty action list wipes every earlier
        // service's rows (incident 2026-09-02: bank8-payments-worker's
        // empty section erased bank8-fdx's fdx_consent_start, breaking the
        // BFF action proxy → FDX consent start 404).
        sqlx::query("DELETE FROM sys.service_actions WHERE vertical = $1 AND service_type = $2")
            .bind(vertical)
            .bind(service_type)
            .execute(pool)
            .await?;
        for sa in actions {
            let action = sa.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let sa_service = sa
                .get("service_type")
                .and_then(|v| v.as_str())
                .unwrap_or(service_type);
            let platform_domain_key = sa
                .get("platform_domain_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let method = sa.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let endpoint = sa.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
            let scope = sa.get("scope").and_then(|v| v.as_str()).unwrap_or("");
            sqlx::query(
                r#"INSERT INTO sys.service_actions (vertical, action, service_type, platform_domain_key, method, endpoint, scope)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT (action, vertical) DO UPDATE
                     SET service_type = EXCLUDED.service_type,
                         platform_domain_key = EXCLUDED.platform_domain_key,
                         method = EXCLUDED.method,
                         endpoint = EXCLUDED.endpoint,
                         scope = EXCLUDED.scope"#,
            )
            .bind(vertical)
            .bind(action)
            .bind(sa_service)
            .bind(platform_domain_key)
            .bind(method)
            .bind(endpoint)
            .bind(scope)
            .execute(pool)
            .await?;
        }
        if !actions.is_empty() {
            println!("    Registered {} service actions", actions.len());
        }
    }

    // Upsert M2M DCR scope grants (self-registration §3.11 — incident
    // 2026-09-09: no grant rows for vertical workloads fail-closed every
    // vertical bus/policy/stat DCR; ~7,600 "DCR pending" consume-loop
    // warnings in one day). Target-state keying (auth design §4.3c): rows
    // are keyed by `service_name` — the gate matches the presented
    // Acme-signed client certificate's subject `CN` against this key, so
    // no thumbprint provisioning is needed (the cert is minted on demand
    // at first boot) and no `certless:` placeholder rows exist. Idempotent
    // upsert. The grants table is created by auth's init.sql; guard the
    // insert so enroll against a pre-auth DB degrades to a warning instead
    // of failing the whole registration.
    if let Some(grants) = m2m_grants_json.and_then(|v| v.as_array()) {
        for g in grants {
            let workload = g.get("workload").and_then(|v| v.as_str()).unwrap_or("");
            let scopes: Vec<String> = g
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if workload.is_empty() || scopes.is_empty() {
                continue;
            }
            // VDC-2/VDC-4: stamp the workload's vertical + owning service —
            // Auth embeds `vertical` as the M2M token claim (Bus enforces
            // event-type ownership on produce); Sys's tenant-snapshot API
            // resolves the caller's service via `service_type` for scoped
            // discovery. The registry's fields are the source of truth
            // (workload names are inconsistent — some bare like
            // `ledger-audit`, some full identities).
            match sqlx::query(
                r#"INSERT INTO auth.m2m_scope_grants
                   (service_name, allowed_scopes, vertical, service_type)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (service_name) DO UPDATE
                     SET allowed_scopes = EXCLUDED.allowed_scopes,
                         vertical = EXCLUDED.vertical,
                         service_type = EXCLUDED.service_type"#,
            )
            .bind(workload)
            .bind(&scopes)
            .bind(vertical)
            .bind(service_type)
            .execute(pool)
            .await
            {
                Ok(_) => {}
                Err(sqlx::Error::Database(db)) if db.message().contains("does not exist") => {
                    println!(
                        "    WARNING: auth.m2m_scope_grants missing — run auth init.sql first (grant '{workload}' skipped)"
                    );
                }
                Err(e) => return Err(anyhow::anyhow!("m2m grant upsert '{workload}': {e}")),
            }
        }
        if !grants.is_empty() {
            println!("    Registered {} M2M scope grants", grants.len());
        }

        // Group DESIGN.md §3.1: provision the workload's Valkey ACL user —
        // the cert-CN→user mapping needs a user of the same name, and the
        // vertical's `valkey` fragment section extends its key/command
        // surface when declared.
        let workloads: Vec<String> = grants
            .iter()
            .filter_map(|g| {
                let w = g.get("workload")?.as_str()?;
                (!w.is_empty()).then(|| w.to_string())
            })
            .collect();
        provision_workload_acl_users(
            &workloads,
            &valkey_acl
                .map(|a| a.key_patterns.clone())
                .unwrap_or_default(),
            &valkey_acl.map(|a| a.commands.clone()).unwrap_or_default(),
            valkey_conn,
        )
        .await?;

        // auth DESIGN §4.3f: publish the token-free M2M
        // authorization map. The grant rows above remain the durable
        // record; this Valkey hash is the TRANSPORT every service
        // boot-loads and TTL-caches (Shield scopes, Bus's VDC-2 vertical
        // gate, revocation via `enabled`). Published whole-per-SERVICE:
        // only THIS service's stale fields are removed (a vertical owns
        // many services — a vertical-keyed sweep would wipe siblings'
        // entries on every pass), then the fresh set lands.
        let map_entries: Vec<(String, sentin8::auth::workload_registry::WorkloadRecord)> = grants
            .iter()
            .filter_map(|g| {
                let workload = g.get("workload")?.as_str()?.to_string();
                let scopes: Vec<String> = g
                    .get("scopes")?
                    .as_array()?
                    .iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect();
                if workload.is_empty() || scopes.is_empty() {
                    return None;
                }
                Some((
                    workload,
                    sentin8::auth::workload_registry::WorkloadRecord {
                        vertical: vertical.to_string(),
                        service_type: service_type.to_string(),
                        scopes,
                        enabled: true,
                    },
                ))
            })
            .collect();
        let valkey_url = std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(sentin8::config::service_valkey_url);
        match sentin8::auth::workload_registry::publish_service(&valkey_url, &map_entries).await {
            Ok(()) => {
                if !map_entries.is_empty() {
                    println!(
                        "    Published {} workload registry entries (m2m:workloads)",
                        map_entries.len()
                    );
                }
            }
            Err(e) => {
                // The map is the authorization record for the token-free
                // plane — a silent skip would leave services serving stale
                // authorization. Enroll fails loudly.
                return Err(anyhow::anyhow!(
                    "workload registry publish failed for service '{service_type}': {e} — \
                     is Valkey up?"
                ));
            }
        }
    }

    // Derive CLI commands from the OpenAPI spec (SELFREG-18).
    // Each path+method with an operationId becomes a CLI command:
    //   command   = service tag (e.g. "auth")
    //   subcommand = noun from operationId (e.g. "user")
    //   action    = verb from operationId (e.g. "list")
    //   scope     = security scope from OpenAPI (or "")
    //   args      = parameters from OpenAPI
    if let Some(openapi) = openapi_json {
        let cli_cmds = derive_cli_commands_from_openapi(openapi, vertical, service_type);
        if !cli_cmds.is_empty() {
            // Clear old CLI commands for this service+vertical.
            sqlx::query("DELETE FROM sys.cli_commands WHERE vertical = $1 AND command = $2")
                .bind(vertical)
                .bind(cli_cmds[0].command.as_str())
                .execute(pool)
                .await?;
            for cmd in &cli_cmds {
                sqlx::query(
                    r#"INSERT INTO sys.cli_commands (vertical, command, subcommand, action, method, path, scope, args)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                       ON CONFLICT (vertical, command, subcommand, action) DO UPDATE
                         SET method = EXCLUDED.method,
                             path = EXCLUDED.path,
                             scope = EXCLUDED.scope,
                             args = EXCLUDED.args"#,
                )
                .bind(vertical)
                .bind(&cmd.command)
                .bind(&cmd.subcommand)
                .bind(&cmd.action)
                .bind(&cmd.method)
                .bind(&cmd.path)
                .bind(&cmd.scope)
                .bind(serde_json::to_value(&cmd.args).unwrap_or(serde_json::Value::Array(vec![])))
                .execute(pool)
                .await?;
            }
            println!(
                "    Registered {} CLI commands from OpenAPI",
                cli_cmds.len()
            );
        }
    }

    println!("  Registered service: {service_type}");
    Ok(())
}

/// A CLI command derived from an OpenAPI path+method.
#[derive(Debug, Clone)]
struct DerivedCliCommand {
    command: String,
    subcommand: String,
    action: String,
    method: String,
    path: String,
    scope: String,
    args: Vec<DerivedCliArg>,
}

/// A CLI command argument derived from an OpenAPI parameter.
#[derive(Debug, Clone, serde::Serialize)]
struct DerivedCliArg {
    name: String,
    kind: String,
    required: bool,
    secret: bool,
    position: Option<String>,
}

/// Derive CLI commands from an OpenAPI 3.1 spec.
///
/// Each path+method with an `operationId` becomes a CLI command. The
/// `operationId` follows the pattern `verb_noun` (e.g. `list_users`,
/// `create_user`, `revoke_api_key`), which maps to:
///   - `command`   = the OpenAPI tag (e.g. "auth")
///   - `subcommand` = the noun, singularized (e.g. "users" → "user")
///   - `action`    = the verb (e.g. "list", "create", "revoke")
///
/// Parameters become CLI args with `kind` = "query" or "path", and
/// `position` = the path suffix after the parameter for path params.
fn derive_cli_commands_from_openapi(
    openapi: &serde_json::Value,
    _vertical: &str,
    service_type: &str,
) -> Vec<DerivedCliCommand> {
    let paths = match openapi.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return vec![],
    };

    let mut commands = vec![];

    for (path, methods) in paths {
        let method_obj = match methods.as_object() {
            Some(m) => m,
            None => continue,
        };

        for (method, detail) in method_obj {
            // Skip non-HTTP methods (parameters, summary, etc).
            let method_upper = match method.as_str() {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "delete" => "DELETE",
                "patch" => "PATCH",
                _ => continue,
            };

            let operation_id = match detail.get("operationId").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };

            // Derive command from tag (first tag, or service_type without vertical prefix).
            let tag = detail
                .get("tags")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or(service_type);

            // Strip the vertical prefix from the tag to derive the command
            // group: `sentin8:ledger` → `ledger` (platform tags drop the
            // `sentin8` segment), `bank8:ledger` → `ledger`. Colon identity
            // (architecture-principles.md §6.0) with legacy hyphen fallback.
            let command = if let Some((_, rest)) = tag.split_once(':') {
                // `sentin8:auth` → `auth`; multi-segment tags take the
                // segment before the resource (first two segments).
                let segs: Vec<&str> = rest.split(':').collect();
                if segs.len() >= 2 && segs[0] == "sentin8" {
                    segs[1..].join(":")
                } else {
                    segs[0].to_string()
                }
            } else {
                tag.rsplit_once('-')
                    .map(|(_, rest)| rest)
                    .unwrap_or(tag)
                    .to_string()
            };

            // operation_id format: "subcommand.action" (e.g. "user.list", "api-key.create").
            // If no dot, fall back to the auto-generated pattern "verb_noun".
            let (subcommand, action) = if let Some((sub, act)) = operation_id.split_once('.') {
                (sub.to_string(), act.to_string())
            } else {
                // Auto-generated operationId: "list_users" → verb="list", noun="users"
                let parts: Vec<&str> = operation_id.splitn(2, '_').collect();
                if parts.len() < 2 {
                    // Single-word operationId — use as action, first path segment as subcommand.
                    let action = parts[0].to_string();
                    let subcommand = path
                        .split('/')
                        .find(|s| !s.is_empty())
                        .unwrap_or("root")
                        .to_string();
                    (subcommand, action)
                } else {
                    let action = parts[0].to_string();
                    let noun = parts[1].to_string();
                    // Singularize simple plurals: "users" → "user", "roles" → "role".
                    let sub =
                        if noun.ends_with('s') && !noun.ends_with("ss") && !noun.ends_with("us") {
                            noun[..noun.len() - 1].to_string()
                        } else {
                            noun
                        };
                    (sub, action)
                }
            };

            commands.push(DerivedCliCommand {
                command,
                subcommand,
                action,
                method: method_upper.to_string(),
                path: path.clone(),
                scope: extract_scope(detail),
                args: extract_args(detail, path),
            });
        }
    }

    commands
}

/// Extract the security scope from an OpenAPI operation.
/// Returns the first scope key from the security array, or empty string.
fn extract_scope(detail: &serde_json::Value) -> String {
    if let Some(security) = detail.get("security").and_then(|v| v.as_array()) {
        for req in security {
            if let Some(obj) = req.as_object() {
                if let Some(key) = obj.keys().next() {
                    return key.clone();
                }
            }
        }
    }
    String::new()
}

/// Extract CLI args from OpenAPI parameters.
fn extract_args(detail: &serde_json::Value, path: &str) -> Vec<DerivedCliArg> {
    let mut args = vec![];
    if let Some(params) = detail.get("parameters").and_then(|v| v.as_array()) {
        for param in params {
            let name = param
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let kind = param
                .get("in")
                .and_then(|v| v.as_str())
                .unwrap_or("query")
                .to_string();
            let required = param
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // For path params, compute the position (path suffix after the param).
            let position = if kind == "path" {
                // Find the param in the path and return everything after it.
                let marker = format!("{{{name}}}");
                path.find(&marker).map(|idx| {
                    let suffix = &path[idx + marker.len()..];
                    if suffix.is_empty() {
                        suffix.to_string()
                    } else {
                        suffix.trim_start_matches('/').to_string()
                    }
                })
            } else {
                None
            };

            args.push(DerivedCliArg {
                name,
                kind,
                required,
                secret: false,
                position,
            });
        }
    }
    args
}

/// Register apps from a vertical registry: upsert listings into PostgreSQL
/// and register web directory paths in Valkey for web discovery.
///
/// This is the legacy path — now a no-op since the registry no longer has
/// inline app data. All app registration is handled by `register_apps_from_dir`
/// which reads `app.json` files listed in the registry's `apps` array.
async fn register_apps(
    _registry: &VerticalRegistry,
    _registry_path: &str,
    _valkey_conn: &glide::GlideClient,
    _pool: &sqlx::PgPool,
) -> anyhow::Result<()> {
    // No-op — register_apps_from_dir handles all app registration via app.json files.
    Ok(())
}

/// Unregister a vertical domain from the platform.
pub async fn unregister(vertical: &str) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    println!("Unenrolling vertical: {}", vertical);

    // 1. Remove known verticals from Valkey (the operator's admin
    // identity — same as enroll).
    let valkey_url = std::env::var("VALKEY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(sentin8::config::service_valkey_url);
    let valkey_conn = open_admin_valkey_conn(&valkey_url).await?;
    valkey_conn
        .custom_command(&["SREM", "captain:known_verticals", vertical])
        .await
        .map_err(|e| anyhow::anyhow!("SREM known verticals: {e}"))?;

    // 2. Remove cross-service endpoint URLs from Valkey (best-effort —
    // we don't know which env vars were registered, so we scan).
    let pattern = format!("captain:vertical_endpoint:*{vertical}*");
    let keys: Vec<String> = valkey_cmd_strings(&valkey_conn, "KEYS", &[&pattern]).await;
    for key in &keys {
        let _ = valkey_conn.custom_command(&["DEL", key]).await;
    }

    // 3. Remove service definitions, consent providers, error codes and audit findings.
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    let pool = sentin8::config::pg_pool::connect(&db_url).await?;

    sqlx::query("DELETE FROM sys.vertical_services WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.consent_providers WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.service_actions WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.vertical_error_codes WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.vertical_audit_findings WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.vertical_admin_scopes WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.consent_flows WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM sys.cli_commands WHERE vertical = $1")
        .bind(vertical)
        .execute(&pool)
        .await?;

    // 4. Remove app listings owned by this vertical and app dir keys from Valkey.
    // App slugs follow the pattern `{domain}-*` (e.g. `bank8-ebank`).
    sqlx::query("DELETE FROM app.store_listings WHERE app_slug LIKE $1")
        .bind(format!("{}-%", vertical))
        .execute(&pool)
        .await?;
    let pattern = format!("captain:app_dir:{}-*", vertical);
    let app_keys: Vec<String> = valkey_cmd_strings(&valkey_conn, "KEYS", &[&pattern]).await;
    for key in &app_keys {
        let _ = valkey_conn.custom_command(&["DEL", key]).await;
    }

    println!("Vertical '{}' unenrolled.", vertical);
    Ok(())
}

/// `--print-registration --section=event_triggers` output (SELFREG):
/// declarative event→function bindings (event-driven execution §4.5).
/// Rows land in `sys.event_triggers` (created on demand — a fresh
/// platform has no triggers table until a service declares one). Idempotent
/// upsert on (service, event_type, consumer_group).
pub(crate) async fn upsert_registration_event_triggers(
    pool: &sqlx::PgPool,
    service: &str,
    triggers: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let Some(arr) = triggers.and_then(|v| v.as_array()) else {
        return Ok(());
    };
    if arr.is_empty() {
        return Ok(());
    }
    // Table is created on demand (fresh-platform rule: no migrations for old
    // data; the enroll path owns the schema bootstrap for this table).
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sys.event_triggers (
            id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            service        TEXT NOT NULL,
            event_type     TEXT NOT NULL,
            target         JSONB NOT NULL DEFAULT '{}',
            consumer_group TEXT NOT NULL,
            retry          JSONB NOT NULL DEFAULT '{}',
            created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (service, event_type, consumer_group)
        )"#,
    )
    .execute(pool)
    .await?;

    for entry in arr {
        let event_type = entry
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let consumer_group = entry
            .get("consumer_group")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if event_type.is_empty() || consumer_group.is_empty() {
            continue;
        }
        let target = entry
            .get("target")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let retry = entry.get("retry").cloned().unwrap_or(serde_json::json!({}));
        sqlx::query(
            r#"INSERT INTO sys.event_triggers (service, event_type, target, consumer_group, retry)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (service, event_type, consumer_group)
               DO UPDATE SET target = $3, retry = $5"#,
        )
        .bind(service)
        .bind(event_type)
        .bind(&target)
        .bind(consumer_group)
        .bind(&retry)
        .execute(pool)
        .await?;
    }
    println!("event_triggers enrolled for {service}: {}", arr.len());
    Ok(())
}

/// `--print-registration --section=schedules` output (SDD §2.4):
/// declarative recurring schedules (`ScheduleDecl`) provisioned into
/// `cron.schedules` (platform DB — cron is a platform service serving the
/// whole fleet). Idempotent upsert on (env_id, domain, schedule_type):
/// re-enroll updates the expression/target in place. The CLI resolves
/// `baseUrl` from the platform domain at enroll time; the declaration's
/// `target_config` fragment (internalPath, scheduleType) merges into
/// cron's `target_config` JSONB.
pub(crate) async fn upsert_registration_schedules(
    pool: &sqlx::PgPool,
    service: &str,
    subdomain: &str,
    schedules: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let Some(arr) = schedules.and_then(|v| v.as_array()) else {
        return Ok(());
    };
    if arr.is_empty() {
        return Ok(());
    }
    let base_url = format!(
        "https://{}",
        sentin8::config::Sentin8Config::from_env().platform_domain(service),
    );
    for entry in arr {
        let schedule_type = entry
            .get("schedule_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cron_expression = entry
            .get("cron_expression")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if schedule_type.is_empty() || cron_expression.is_empty() {
            continue;
        }
        let timezone = entry
            .get("timezone")
            .and_then(|v| v.as_str())
            .unwrap_or("UTC");
        let max_retries = entry
            .get("max_retries")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as i32;
        // Merge the declared fragment into cron's target_config: baseUrl
        // (CLI-resolved) + the fragment's internalPath/scheduleType.
        let mut target: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        target.insert("baseUrl".into(), serde_json::json!(base_url));
        let fragment = entry.get("target_config").and_then(|v| v.as_str());
        if let Some(frag) = fragment.and_then(|f| serde_json::from_str::<serde_json::Value>(f).ok())
        {
            if let Some(map) = frag.as_object() {
                for (k, v) in map {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
        let target = serde_json::Value::Object(target);
        // The SYSTEM env owns platform-declared internal schedules (cron's
        // schedules table is env-scoped; enroll provisions the platform
        // env row — the same env the proxy-back handler resolves).
        sqlx::query(
            r#"INSERT INTO cron.schedules
                   (domain, schedule_type, cron_expression, target_config, timezone,
                    max_retries, env_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (env_id, domain, schedule_type) DO UPDATE
                   SET cron_expression = $3,
                       target_config    = $4,
                       timezone        = $5,
                       max_retries     = $6,
                       updated_at      = now()"#,
        )
        .bind(subdomain)
        .bind(schedule_type)
        .bind(cron_expression)
        .bind(&target)
        .bind(timezone)
        .bind(max_retries)
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(pool)
        .await?;
    }
    println!("schedules enrolled for {service}: {}", arr.len());
    Ok(())
}
