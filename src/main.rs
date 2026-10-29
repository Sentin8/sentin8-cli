// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 unified CLI - device flow auth + platform management.
//!
//! See `sentin8/design/sentin8-sentin8-cli-technical-design.md`.
//!
//! Usage:
//!   sentin8 signin                          - OAuth 2.0 Device Authorization Grant
//!   sentin8 signout                          - revoke token, clear credentials
//!   sentin8 whoami                           - show current user, scopes, expiry
//!   sentin8 config set <key> <value>         - set config value
//!   sentin8 config get <key>                 - get config value
//!   sentin8 func upload   --domain=... ...  - upload a WASM module
//!   sentin8 func validate --wasm=...        - validate a WASM binary locally
//!   sentin8 func download --module-id=...   - download a module binary
//!   sentin8 func list-versions --domain=... - list module versions
//!   sentin8 func bulk-upload --manifest=... - bulk upload from manifest
//!   sentin8 captain start                   - start captain (launches the whole platform)
//!   sentin8 captain stop                    - stop captain (gracefully brings down the platform)
//!   sentin8 captain restart                 - stop + start captain
//!   sentin8 captain services                - list all service instances
//!   sentin8 captain services --type=bff    - filter by service type
//!   sentin8 captain services --status=Active - filter by status
//!   sentin8 captain catalog                 - list the static service catalog
//!   sentin8 captain restart-instance <key>  - restart a service instance
//!   sentin8 captain stop-instance <key>     - stop a service instance
//!   sentin8 captain start-instance <key>    - start a stopped instance
//!   sentin8 captain upgrade-instance <key>  - rolling upgrade of a service instance

#[allow(dead_code)]
mod auth;
mod call;
#[allow(dead_code)]
mod captain;
mod commands;
#[allow(dead_code)]
mod config;
mod db;
#[allow(dead_code)]
mod func;
#[allow(dead_code)]
mod infra;
#[allow(dead_code)]
mod secrets;
#[allow(dead_code)]
mod transport;
mod registration;
mod vertical_registry;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sentin8", version, about = "Sentin8 unified CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign in using OAuth 2.0 Device Authorization Grant.
    Signin {
        #[arg(long, env = "SENTIN8_SENTIN8_AUTH_URL")]
        sentin8_auth_url: Option<String>,
        #[arg(long, env = "SENTIN8_CLIENT_ID", default_value = "sentin8-cli")]
        client_id: String,
        #[arg(long, default_value = "openid profile email offline_access")]
        scope: String,
    },
    /// Sign up a new user account (calls POST /v1/sign-up).
    Signup {
        #[arg(long, env = "SENTIN8_SENTIN8_AUTH_URL")]
        sentin8_auth_url: Option<String>,
        /// Email address for the new account.
        #[arg(long)]
        email: String,
        /// Password (min 8 characters).
        #[arg(long)]
        password: String,
        /// Optional first name.
        #[arg(long)]
        first_name: Option<String>,
        /// Optional last name.
        #[arg(long)]
        last_name: Option<String>,
        /// Automatically initiate device-flow sign-in after signup.
        #[arg(long, short = 's')]
        signin: bool,
    },
    /// Sign out - revoke token and clear credentials.
    Signout,
    /// Show current user, scopes, and token expiry.
    Whoami,
    /// Config management.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Func WASM module management.
    Func {
        #[command(subcommand)]
        command: func::FuncCommand,
    },
    /// Captain process supervisor management.
    Captain {
        #[command(subcommand)]
        command: captain::CaptainCommand,
    },
    /// Database management (reset / migrate).
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Tenant secret management (Sentin8:Secrets).
    Secrets {
        #[command(subcommand)]
        command: secrets::SecretsCommand,
    },
    /// Vertical registry management (init / enroll / unenroll vertical domains).
    Vertical {
        #[command(subcommand)]
        command: VerticalCommand,
    },
    /// List all declarative CLI commands registered in the platform
    /// (from `sentin8_cli_commands`, populated by `vertical enroll`).
    // The user-facing subcommand IS `list-commands` (a platform-registered
    // surface, CLI DESIGN §9) - the variant name mirrors it by contract.
    #[allow(clippy::enum_variant_names)]
    ListCommands,
    /// Generic service passthrough - `call <service> <method> <path>`.
    /// Resolves the service URL from the runtime registry and dispatches
    /// with the stored token. No registry entry needed. See §9.5.
    Call {
        /// Service name (e.g. `auth`, `sys`, `bank8-ledger`).
        service: String,
        /// HTTP method (GET, POST, PUT, DELETE, PATCH).
        method: String,
        /// Endpoint path (e.g. `/v1/admin/users`).
        path: String,
        /// JSON body for POST/PUT/PATCH.
        #[arg(long)]
        body: Option<String>,
        /// Target environment ID (defaults to config defaultEnvId or system env).
        #[arg(long)]
        env: Option<String>,
    },
    /// Declarative service command - `do <command> <subcommand> <action> [--field value ...]`.
    /// Dispatches via the generic executor reading `sentin8_cli_commands`.
    /// Use `list-commands` to see what's registered. See §9.
    Do {
        /// Command group (e.g. `auth`, `sys`, `ledger`).
        command: String,
        /// Resource noun (e.g. `user`, `org`, `account`).
        subcommand: String,
        /// Verb (e.g. `list`, `create`, `get`, `update`, `delete`).
        action: String,
        /// Target environment ID (defaults to config defaultEnvId or system env).
        #[arg(long)]
        env: Option<String>,
        /// Field/path/query arguments as --key=value pairs.
        #[arg(allow_hyphen_values = true)]
        fields: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Set a config value.
    Set { key: String, value: String },
    /// Get a config value.
    Get { key: String },
}

#[derive(Subcommand)]
enum DbCommand {
    /// One-time platform initialization .
    ///
    /// Applies platform + service SQL, seeds the registry tables, generates
    /// the bootstrap admin password (printed ONCE), and writes the
    /// `sys.platform_bootstrap` scout. Requires only the database
    /// username/password - Auth does not exist yet. Refuses when the platform
    /// is already initialized; destructive reset does not exist in the
    /// platform CLI (local dev: scripts/dev-destroy.sh, needs SENTIN8_DEV=1).
    Bootstrap {
        /// Operator note recorded in the scout (who/why bootstrapped).
        #[arg(long)]
        operator_note: Option<String>,
    },
    /// Mark the bootstrap window closed after `vertical enroll`
    /// : writes `finalized_at` on the scout. Credential-free -
    /// the seed a@m.n/pass credential stays valid until the operator
    /// changes it via self-service. Idempotent (second run is a no-op).
    Finalize,
    /// Re-apply init scripts without dropping.
    Migrate {
        /// Extra SQL directory to scan (in addition to sentin8/services/*/sql).
        #[arg(long, env = "SENTIN8_DB_SQL_DIRS")]
        sql_dirs: Option<String>,
    },
    /// Auto-register apps from app-listing.json manifests.
    ///
    /// Scans all domain apps/ directories for app-listing.json files
    /// and upserts them into the sentin8_app_store_listings table. Also runs
    /// automatically during `db reset`.
    #[command(name = "seed-listings")]
    SeedListings {
        /// Extra apps directory to scan (in addition to sentin8/apps/).
        /// Can be repeated or comma-separated for multiple domains.
        #[arg(long, env = "SENTIN8_DB_APPS_DIRS")]
        apps_dirs: Option<String>,
    },
}

#[derive(Subcommand)]
enum VerticalCommand {
    /// Initialize a vertical's database schema (creates tables from sql_dirs).
    ///
    /// Reads a vertical-registry.json file and applies all SQL files
    /// from the `sql_dirs` entries. This must be run BEFORE `vertical enroll`
    /// and BEFORE starting services - services assume tables already exist.
    ///
    /// **Composable (RS §6)**: accepts repo directories (containing
    /// `service-registration.json`) and/or legacy aggregate registry files.
    Init {
        /// Paths: repo directories and/or vertical-registry.json files.
        #[arg(value_name = "PATH")]
        registry: Vec<String>,
    },
    /// Enroll a vertical domain with the platform.
    ///
    /// Reads a vertical-registry.json file and enrolls the vertical's services,
    /// error codes, apps, and audit findings. For services with a `binary` field,
    /// runs each binary with `--print-registration` to get all registration data
    /// (scopes, error codes, admin_ui, SQL migrations, OpenAPI spec) from the
    /// service itself - no need for the service to be running. Also scans
    /// `apps/*/app.json` for app listings.
    ///
    /// **Composable enrollment (RS §6)**: accepts ANY MIX of paths - repo
    /// directories (auto-locating `service-registration.json` + `catalog.json`)
    /// and legacy aggregate `vertical-registry.json` files. A team can enroll
    /// a few services/apps from a vertical without the whole vertical.
    Enroll {
        /// Paths: repo directories (containing service-registration.json)
        /// and/or legacy vertical-registry.json files.
        #[arg(value_name = "PATH")]
        registry: Vec<String>,
    },
    /// Unenroll a vertical from the platform.
    Unenroll {
        /// Vertical name to unenroll (e.g. "bank8").
        vertical: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Self-description first (RS §6 self-registration contract, the shell's
    // step-1 semantics): flag check BEFORE any provider install, banner, env
    // load, or network - the enroll probe must succeed in a bare environment.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return registration::print(section);
    }

    // Install the Graviola crypto provider before any reqwest HTTPS call.
    // The workspace reqwest uses rustls-tls-native-roots-no-provider, which
    // requires an explicit crypto provider installation.
    let _ = rustls_graviola::default_provider().install_default();

    println!(
        "{} v{} (build {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        // the git short hash stamped at build time ("unknown"
        // for ad-hoc, unstamped builds - an EMPTY stamp, the vendored-
        // source fallback, renders "unknown" too, never a blank).
        sentin8::build_info::git_sha()
            .filter(|sha| !sha.is_empty())
            .unwrap_or("unknown")
    );
    let cli = Cli::parse();
    match cli.command {
        Commands::Signin {
            sentin8_auth_url,
            client_id,
            scope,
        } => {
            auth::signin(sentin8_auth_url.as_deref(), &client_id, &scope).await?;
        }
        Commands::Signup {
            sentin8_auth_url,
            email,
            password,
            first_name,
            last_name,
            signin,
        } => {
            auth::signup(
                sentin8_auth_url.as_deref(),
                &email,
                &password,
                first_name.as_deref(),
                last_name.as_deref(),
                signin,
            )
            .await?;
        }
        Commands::Signout => {
            auth::signout().await?;
        }
        Commands::Whoami => {
            auth::whoami()?;
        }
        Commands::Config { command } => match command {
            ConfigCommand::Set { key, value } => config::set(&key, &value)?,
            ConfigCommand::Get { key } => config::get(&key)?,
        },
        Commands::Func { command } => {
            let token = auth::get_valid_token().await?;
            func::run(command, &token).await?;
        }
        Commands::Captain { command } => {
            captain::run(command).await?;
        }
        Commands::Db { command } => match command {
            DbCommand::Bootstrap { operator_note } => {
                db::bootstrap(operator_note.as_deref()).await?
            }
            DbCommand::Finalize => db::finalize().await?,
            DbCommand::Migrate { sql_dirs } => db::migrate(&sql_dirs).await?,
            DbCommand::SeedListings { apps_dirs } => db::seed_listings(&apps_dirs).await?,
        },
        Commands::Secrets { command } => {
            secrets::run(command).await?;
        }
        Commands::Vertical { command } => match command {
            VerticalCommand::Init { registry } => {
                // Composable (RS §6): init applies each repo/aggregate in
                // order; an empty list is an error (no implicit discovery).
                anyhow::ensure!(!registry.is_empty(), "no init paths given");
                for path in &registry {
                    vertical_registry::init_vertical(path).await?
                }
            }
            VerticalCommand::Enroll { registry } => {
                // Composable enrollment (RS §6): each path is either a repo
                // dir (service-registration.json fragment) or a legacy
                // aggregate vertical-registry.json; merge them all.
                vertical_registry::register_paths(&registry).await?
            }
            VerticalCommand::Unenroll { vertical } => {
                vertical_registry::unregister(&vertical).await?
            }
        },
        Commands::ListCommands => {
            commands::list_commands().await?;
        }
        Commands::Call {
            service,
            method,
            path,
            body,
            env,
        } => {
            call::execute(&service, &method, &path, body.as_deref(), env.as_deref()).await?;
        }
        Commands::Do {
            command,
            subcommand,
            action,
            env,
            fields,
        } => {
            let (field_args, path_args) = parse_field_args(&fields)?;
            commands::execute(
                &command,
                &subcommand,
                &action,
                &field_args,
                &path_args,
                env.as_deref(),
            )
            .await?;
        }
    }
    Ok(())
}

/// Parse `--key=value` and `--key value` pairs from the command line into
/// a map of field args and path args. Path args are identified by the
/// command's arg definitions (kind="path") - but at the CLI parsing level
/// we treat all `--key=value` as field args and let the executor decide
/// which are path vs query vs field based on the command definition.
fn parse_field_args(
    fields: &[String],
) -> anyhow::Result<(
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
)> {
    let mut field_args = std::collections::HashMap::new();
    let mut path_args = std::collections::HashMap::new();
    let mut i = 0;
    while i < fields.len() {
        let field = &fields[i];
        if let Some(rest) = field.strip_prefix("--") {
            if let Some((key, value)) = rest.split_once('=') {
                // --key=value
                field_args.insert(key.to_string(), value.to_string());
                path_args.insert(key.to_string(), value.to_string());
            } else if i + 1 < fields.len() && !fields[i + 1].starts_with("--") {
                // --key value (next arg is the value)
                field_args.insert(rest.to_string(), fields[i + 1].clone());
                path_args.insert(rest.to_string(), fields[i + 1].clone());
                i += 1;
            } else {
                // --flag (boolean, set to "true")
                field_args.insert(rest.to_string(), "true".to_string());
            }
        }
        i += 1;
    }
    Ok((field_args, path_args))
}
