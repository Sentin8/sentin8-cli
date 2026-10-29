// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Captain subcommands - manage the process supervisor and its services.
//!
//! Platform-level commands:
//!   sentin8 captain start                   - start captain (launches the whole platform)
//!   sentin8 captain start <types>           - ensure specific types (ONE comma-joined
//!                                             token string; split/canonicalized into
//!                                             the API list or the boot allow-list -
//!, DESIGN §4.1)
//!   sentin8 captain stop                    - stop captain (gracefully brings down the platform)
//!   sentin8 captain restart                 - stop + start captain
//!
//! Query commands:
//!   sentin8 captain services                - list all service instances
//!   sentin8 captain services --type=bff    - filter by service type
//!   sentin8 captain services --status=Active - filter by status
//!   sentin8 captain catalog                 - list the static service catalog
//!
//! Per-instance commands:
//!   sentin8 captain restart-instance <key>  - restart a service instance
//!   sentin8 captain stop-instance <key>     - stop a service instance
//!   sentin8 captain start-instance <key>    - start a stopped instance
//!   sentin8 captain upgrade-instance <key>  - rolling upgrade of a service instance
//!
//! Identity: every captain API call attaches the signed-in operator's token
//! (device flow, cached credentials) best-effort - the management API is
//! Shield-gated on `sentin8:captain:admin` (design §6.1/§9), so without a
//! token the endpoints reject with 401/403. Once the platform is
//! bootstrapped (`sys.platform_bootstrap` scout exists), the
//! lifecycle commands `start`/`restart`/`stop` REQUIRE the signed-in
//! operator (DEVUI-1.3): the SIGTERM/direct-spawn fallbacks only run in the
//! pre-scout window (Auth not up yet - bootstrap/CI). `start`/`restart`
//! stream progress best-effort and degrade to a hint instead of hanging.
//!
//! Local control channel (DEVUI-2.1, captain design §6.1.2): when no remote
//! captain URL is configured and the local UDS control socket exists, every
//! command talks over the socket and the sign-in gate is SKIPPED - the
//! kernel-proven peer uid (root or socket owner) is the authorization
//! (systemctl model). Remote URLs keep requiring sign-in.

use clap::Subcommand;
use serde::Deserialize;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;

use crate::config::captain_url;
use crate::transport::{CaptainTransport, UdsClient};

#[derive(Subcommand)]
pub enum CaptainCommand {
    /// Start captain (launches the whole platform - all managed services).
    Start {
        /// The routable IP address of this machine on the network.
        /// Used as the instance key and advertised to other machines via
        /// service discovery. Auto-detected if omitted (first non-loopback IPv4).
        #[arg(long, env = "SENTIN8_CAPTAIN_LOCAL_IP")]
        local_ip: Option<String>,
        /// Comma-separated paths to external service catalog.json files
        /// (e.g. `bank8/services/catalog.json,hotel8/services/catalog.json`).
        /// Captain merges these into its built-in catalog so it knows how
        /// to spawn external domain services.
        #[arg(long, env = "SENTIN8_CAPTAIN_CATALOG_PATHS")]
        catalog_paths: Option<String>,
        /// Optional: ONE comma-separated token string naming the service
        /// types to ensure (e.g. `sentin8: auth, sentin8: bff`).
        /// Split, trimmed, and canonicalized (`sentin8-auth` → `sentin8:auth`)
        /// by the handler. Omitted → the platform-core default (captain's
        /// unset-`SENTIN8_SERVICES` boot behavior,).
        /// Default: start all.
        services: Option<String>,
    },
    /// Stop captain (sends SIGTERM - captain gracefully stops all managed services).
    Stop,
    /// Restart captain (stop + start).
    Restart {
        /// The routable IP address of this machine on the network.
        /// Auto-detected if omitted (first non-loopback IPv4).
        #[arg(long, env = "SENTIN8_CAPTAIN_LOCAL_IP")]
        local_ip: Option<String>,
        /// Comma-separated paths to external service catalog.json files.
        #[arg(long, env = "SENTIN8_CAPTAIN_CATALOG_PATHS")]
        catalog_paths: Option<String>,
    },
    /// Replace the running captain binary with zero service downtime
    /// (SELFUP-1.6, design §4.8b-3): SIGTERM the supervisor ONLY -
    /// managed services keep running - then spawn the successor, whose
    /// boot sweep adopts the untouched fleet. Requires the local UDS
    /// control socket (a remote captain is refused). Pre-flight checks
    /// the successor binary and captures the running captain's SENTIN8_*/
    /// DATABASE_URL/VALKEY_URL environment as the takeover env.
    UpgradeSelf,
    /// List all service instances (optionally filtered).
    Services {
        /// Filter by service type (e.g. bff, auth).
        #[arg(long, short = 't')]
        r#type: Option<String>,
        /// Filter by status (Active, Starting, Stopped, Killed, etc.).
        #[arg(long, short = 's')]
        status: Option<String>,
        /// Show only instances on a specific IP.
        #[arg(long, short = 'i')]
        ip: Option<String>,
        /// Skip the PostgreSQL + Valkey infrastructure summary printed
        /// after the service table.
        #[arg(long)]
        no_infra: bool,
    },
    /// List the static service catalog (desired definitions).
    Catalog,
    /// Restart a service instance by its key (`{service_type}/{ip}:{port}`).
    RestartInstance { key: String },
    /// Gracefully stop a service instance.
    StopInstance { key: String },
    /// Start a stopped service instance.
    StartInstance { key: String },
    /// Rolling upgrade of service instances - start new, wait for Active, drain old, stop old.
    /// Accepts multiple keys for parallel upgrades.
    /// Defaults to SSE streaming; use --poll for periodic polling.
    UpgradeInstance {
        /// One or more instance keys (ip:port) to upgrade in parallel.
        keys: Vec<String>,
        /// Poll progress every 2s instead of SSE streaming.
        #[arg(long)]
        poll: bool,
    },
    /// Show the machine auto-provisioning (cluster-autoscaler) state:
    /// profile, backend, fleet size, elected leader, and any pending
    /// provision/deprovision requests awaiting operator approval
    /// (manual profile, design §4.12).
    Autoscaler,
    /// Approve or reject a pending machine provision/deprovision request
    /// (manual profile, design §4.12.5). Execution goes through the
    /// configured backend (OpenTofu or noop dry-run).
    AutoscalerApprove {
        /// Which pending request: `provision` or `deprovision`.
        #[arg(long)]
        kind: String,
        /// The trigger machine IP of the request.
        #[arg(long)]
        ip: String,
        /// `approve` (execute via the backend) or `reject` (discard).
        #[arg(long)]
        decision: String,
    },
    /// Hand-place a service on a machine (captain DESIGN §11.4):
    /// `POST /v1/captain/instances` on the TARGET machine's captain with
    /// the operator bearer. The target's placement gate is the authority -
    /// a pin elsewhere / anti violation / singleton twin returns 409 with
    /// the refusal reason. This is the operator path of the same surface
    /// the autoscaler leader drives with its `captain-remote` M2M token.
    Place {
        /// The target machine IP (its captain must be reachable on the
        /// captain port).
        #[arg(long)]
        ip: String,
        /// One or more service types to place on that machine.
        services: Vec<String>,
    },
}

/// A crash-loop (give-up) alert (`captain: alerts`): a service
/// captain gave up on after MAX_RESTARTS. `make status` prints these as
/// the "manual intervention required" list after the instance table -
/// the operator sees WHICH services are down and WHERE the boot error
/// lives without opening any other surface. Cleared automatically when
/// the service reaches `Active` again (or via CAPT-ALERT-2's
/// last-resort respawner recovering it).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CaptainAlert {
    service: String,
    restarts: i32,
    reason: String,
    #[serde(default)]
    log_path: String,
    #[serde(default)]
    at: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ServiceInstance {
    key: String,
    service_type: String,
    local_ip: String,
    local_port: u16,
    pid: u32,
    status: String,
    restarts: i32,
    cpu_avg_1m: f32,
    memory_avg_1m: f32,
    #[serde(default)]
    rss_mb_avg_1m: f32,
    latency_avg_1m_ms: f32,
    #[serde(default)]
    last_health_check: Option<i64>,
    #[serde(default)]
    started_at: Option<i64>,
    #[serde(default)]
    version: String,
    /// Compile-time build hash (CAPTAIN-4) - shown as `{version}.{build}`
    /// in the VERSION column so operators can verify WHICH binary runs.
    #[serde(default)]
    build_hash: String,
    #[serde(default)]
    errors: i64,
    #[serde(default)]
    warnings: i64,
    #[serde(default)]
    api_calls: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CatalogEntry {
    service_type: String,
    #[serde(default)]
    binary: String,
    start_priority: i16,
    #[serde(default)]
    fixed_port: u16,
    #[serde(default)]
    web_root: String,
    #[serde(default)]
    use_http_health: bool,
}

// ── PID / signal helpers ───────────────────────────────────────────────

extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
    fn setsid() -> i32;
}

unsafe fn libc_kill(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

fn pid_alive(pid: u32) -> bool {
    unsafe { libc_kill(pid, 0) == 0 }
}

/// Find the captain PID by looking up the management API port.
fn find_captain_pid() -> Option<u32> {
    // Look up by the captain management API port.
    let captain_port = sentin8::config::captain_port();
    let output = std::process::Command::new("lsof")
        .args(["-ti", &format!(":{captain_port}"), "-sTCP:LISTEN"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid_str = stdout.trim().lines().next()?;
    pid_str.parse::<u32>().ok().filter(|&p| pid_alive(p))
}

/// Whether a captain process is alive on this machine :
/// the `start` dispatch picks the API path (up) vs the cold-boot path
/// (down) with this check - the services argument must reach the RIGHT
/// consumer, and a down captain cannot answer the start-services API.
fn captain_up() -> bool {
    find_captain_pid().is_some()
}

/// Parse ONE comma-joined scope argument into the typed service list
/// (DESIGN §4.1). Each segment is trimmed, empty segments
/// are dropped, and every token is canonicalized to the colon identity
/// form (`captain start sentin8-acme,sentin8:bff` → `sentin8:acme`,
/// `sentin8:bff`). This is the seam every group Makefile's scope pin
/// rides on: posting the raw joined string as a single element would
/// match nothing in the captain catalog and no-op the whole start call.
fn parse_scope_list(arg: Option<&str>) -> Vec<String> {
    arg.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(sentin8::config::canonical_service_type)
        .collect()
}

/// Find the sentin8-captain binary.
fn find_captain_binary() -> PathBuf {
    let prefix = std::env::var("SENTIN8_CAPTAIN_BINARY_PREFIX").ok();
    if let Some(prefix) = prefix {
        for dir in prefix.split(':') {
            let path = PathBuf::from(dir).join("sentin8-captain");
            if path.is_file() {
                return path;
            }
        }
        return PathBuf::from(prefix.split(':').next().unwrap_or("")).join("sentin8-captain");
    }
    PathBuf::from("target/release/sentin8-captain")
}

/// Auto-detect the first non-loopback IPv4 address by opening a UDP
/// "connection" to a public address (no packets are actually sent).
/// This picks the interface the kernel would use for outbound traffic,
/// which is the best default for a distributed setup.
fn auto_detect_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Attach the signed-in operator's token to a captain API request,
/// best-effort: without credentials (or with an expired/unrefreshable
/// token) the request goes out bare and the gated endpoint rejects with
/// 401/403 - callers surface that instead of a raw transport error.
/// Over the local UDS (§6.1.2) the kernel-proven peer credentials are the
/// authorization, so the token is unnecessary (attach is still best-effort
/// harmless).
fn attach_operator_token(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match crate::auth::get_valid_token_blocking() {
        Ok(token) => req.bearer_auth(&token),
        Err(_) => req,
    }
}

/// Build the captain API client for the resolved transport (§6.1.2).
///
/// The enum dispatches request execution per transport: over the local
/// control socket the kernel-proven peer credentials authorize the
/// request; over TCP the callers attach the operator token best-effort
/// (as before).
#[derive(Clone)]
enum CaptainApi {
    Tcp(reqwest::Client),
    // Boxed: the UDS transport struct is large relative to the 8-byte
    // reqwest client handle; the enum is cloned per request.
    Unix(Box<UdsClient>),
}

impl CaptainApi {
    /// GET returning `(status, body)`.
    async fn get(&self, path: &str) -> Result<(reqwest::StatusCode, bytes::Bytes), anyhow::Error> {
        match self {
            CaptainApi::Tcp(http) => {
                let url = format!("{}{}", captain_url().trim_end_matches('/'), path);
                let resp = attach_operator_token(http.get(&url)).send().await?;
                let status = resp.status();
                let body = resp.bytes().await?;
                Ok((status, body))
            }
            CaptainApi::Unix(client) => {
                let (st, body) = client.request(hyper::Method::GET, path, None).await?;
                Ok((
                    reqwest::StatusCode::from_u16(st.as_u16())
                        .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                    body,
                ))
            }
        }
    }

    /// POST with a JSON body returning `(status, body)`.
    async fn post_json(
        &self,
        path: &str,
        json: serde_json::Value,
    ) -> Result<(reqwest::StatusCode, bytes::Bytes), anyhow::Error> {
        match self {
            CaptainApi::Tcp(http) => {
                let url = format!("{}{}", captain_url().trim_end_matches('/'), path);
                let resp = attach_operator_token(http.post(&url).json(&json))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.bytes().await?;
                Ok((status, body))
            }
            CaptainApi::Unix(client) => {
                let (st, body) = client
                    .request(hyper::Method::POST, path, Some(json))
                    .await?;
                Ok((
                    reqwest::StatusCode::from_u16(st.as_u16())
                        .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                    body,
                ))
            }
        }
    }
}

fn captain_api_client(transport: &CaptainTransport) -> CaptainApi {
    match transport {
        CaptainTransport::Unix { socket_path } => {
            CaptainApi::Unix(Box::new(UdsClient::new(socket_path.clone())))
        }
        CaptainTransport::Tcp => CaptainApi::Tcp(reqwest::Client::new()),
    }
}

impl CaptainApi {
    /// Open an SSE stream over the resolved transport (§6.1.2).
    async fn request_stream(&self, path: &str) -> Result<SseSource, SseError> {
        sse_connect(&CaptainTransport::resolve(), path).await
    }
}

/// An SSE stream source - either a reqwest byte stream (TCP) or a
/// hyper body stream (UDS). Both yield byte chunks.
enum SseSource {
    Tcp(
        std::pin::Pin<
            Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>,
        >,
    ),
    Unix(http_body_util::BodyDataStream<hyper::body::Incoming>),
}

impl SseSource {
    /// Poll the next byte chunk (unified across transports).
    async fn next_chunk(&mut self) -> Option<Result<bytes::Bytes, std::io::Error>> {
        use futures_util::StreamExt as _;
        match self {
            SseSource::Tcp(stream) => stream
                .next()
                .await
                .map(|c| c.map_err(|e| std::io::Error::other(e.to_string()))),
            // BodyDataStream implements Stream directly (Item = Data).
            SseSource::Unix(stream) => stream
                .next()
                .await
                .map(|c| c.map_err(|e| std::io::Error::other(e.to_string()))),
        }
    }
}

/// Why an SSE connect attempt failed.
enum SseError {
    /// 401/403 - the gate rejected the request (token missing/denied).
    AuthRejected,
    /// Transport failure - retryable (API not up yet, etc.).
    Transport(String),
}

/// Connect to a captain SSE endpoint over the resolved transport.
///
/// TCP path: best-effort operator token attach (the stream endpoints are
/// Shield-gated). UDS path: no token needed - peer credentials authorize.
async fn sse_connect(transport: &CaptainTransport, path: &str) -> Result<SseSource, SseError> {
    match transport {
        CaptainTransport::Unix { socket_path } => {
            let client = UdsClient::new(socket_path.clone());
            let resp = client
                .request_stream(hyper::Method::GET, path)
                .await
                .map_err(|e| SseError::Transport(format!("{e:#}")))?;
            if !resp.status().is_success() {
                if resp.status() == hyper::StatusCode::UNAUTHORIZED
                    || resp.status() == hyper::StatusCode::FORBIDDEN
                {
                    return Err(SseError::AuthRejected);
                }
                return Err(SseError::Transport(format!("HTTP {}", resp.status())));
            }
            use http_body_util::BodyExt;
            Ok(SseSource::Unix(resp.into_body().into_data_stream()))
        }
        CaptainTransport::Tcp => {
            let base = captain_url();
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            let http = reqwest::Client::new();
            let resp = attach_operator_token(http.get(&url))
                .send()
                .await
                .map_err(|e| SseError::Transport(format!("{e}")))?;
            if !resp.status().is_success() {
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN
                {
                    return Err(SseError::AuthRejected);
                }
                return Err(SseError::Transport(format!("HTTP {}", resp.status())));
            }
            Ok(SseSource::Tcp(Box::pin(resp.bytes_stream())))
        }
    }
}

/// Is the platform past its bootstrap/enroll window? The lifecycle gate
/// (DEVUI-1.3) keys on the scout's `finalized_at`, NOT mere scout presence:
/// between `db bootstrap` and `db finalize` the platform has no Auth to
/// sign in against, so the bootstrap sequence itself (`dev-destroy.sh` /
/// CI) MUST be allowed to run `captain start` - a scout-existence gate
/// would deadlock every fresh reset (Auth down → cannot sign in → start
/// refused). Post-finalize, sign-in is possible and required.
/// Checked over a direct `DATABASE_URL` connection - must work while
/// captain is down (post-`stop`). Any connection error returns `true`
/// (fail-closed - when we cannot tell, require sign-in).
fn platform_bootstrapped() -> bool {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".to_string());
    // Blocking shortcut - captain.rs is async, but this check runs before
    // any await point in run(); a lazy future on a dedicated runtime thread
    // keeps the helper sync for reuse in sync contexts.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::try_current().is_ok_and(|h| {
            h.block_on(async {
                let pool = match sqlx::postgres::PgPool::connect(&db_url).await {
                    Ok(p) => p,
                    Err(_) => return true, // DB unreachable → fail-closed.
                };
                // The scout table itself may be missing (pre-bootstrap) -
                // absence means the bootstrap window is still open.
                let finalized = sqlx::query_as::<_, (Option<chrono::DateTime<chrono::Utc>>,)>(
                    "SELECT finalized_at FROM sys.platform_bootstrap WHERE id = 1",
                )
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten();
                let _ = pool.close().await;
                finalized.is_some_and(|f| f.0.is_some())
            })
        })
    })
}

/// Require a signed-in operator (DEVUI-1.3). Post-bootstrap the lifecycle
/// commands must never fall back to signal-level control - UNLESS the
/// command reaches captain over the local control socket (§6.1.2), where
/// the kernel-proven peer uid is the authorization (systemctl model).
fn require_signed_in(command: &str, transport: &CaptainTransport) -> anyhow::Result<String> {
    if transport.is_local_socket() {
        // Peer credentials authorize the request; no operator token needed.
        return Ok(String::new());
    }
    match crate::auth::get_valid_token_blocking() {
        Ok(token) => Ok(token),
        Err(_) => anyhow::bail!(
            "{command} requires signing in once the platform is bootstrapped.\n\
             Run `sentin8-cli signin` and retry - the browser approves the device flow."
        ),
    }
}

/// SELFUP-1.3 (design §4.8b-1): per-instance actions on the captain key
/// target the supervisor itself. Refuse client-side with the operator
/// instruction, before any API call (captain's own handler guard is the
/// backstop; this gives a correct error even when the API can't answer).
fn refuse_captain_key(key: &str, command: &str) -> anyhow::Result<()> {
    if key.contains("sentin8:captain") {
        anyhow::bail!(
            "{command} cannot target the supervisor itself (key '{key}').
Captain can never replace, restart, or stop its own process.
Use `sentin8-cli captain restart` for the control plane (design §4.8b-1)."
        );
    }
    Ok(())
}

/// Upgrade a single instance and wait for completion via SSE streaming or polling.
async fn upgrade_single_instance(client: CaptainApi, key: &str, poll: bool) -> anyhow::Result<()> {
    refuse_captain_key(key, "upgrade-instance")?;
    let path = format!("/v1/captain/services/{}", urlencode(key));
    let (status_code, body) = client
        .post_json(&path, serde_json::json!({"action": "upgrade"}))
        .await?;
    if !status_code.is_success() {
        anyhow::bail!(
            "captain API error: {} {}",
            status_code,
            String::from_utf8_lossy(&body)
        );
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    let status = parsed
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    println!("Upgrade initiated for {} - status: {}", key, status);

    if !poll {
        let stream_path = format!("/v1/captain/upgrade-stream/{}", urlencode(key));
        let mut stream = client
            .request_stream(&stream_path)
            .await
            .map_err(|e| match e {
                SseError::Transport(d) => {
                    anyhow::anyhow!("captain API error: {} (upgrade stream)", d)
                }
                SseError::AuthRejected => {
                    anyhow::anyhow!("upgrade stream requires sign-in - run `sentin8-cli signin`")
                }
            })?;
        let mut buffer = String::new();
        while let Some(chunk) = stream.next_chunk().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(idx) = buffer.find("\n\n") {
                let event_str = buffer[..idx].to_string();
                buffer = buffer[idx + 2..].to_string();
                let mut event_type = String::new();
                let mut data = String::new();
                for line in event_str.lines() {
                    if let Some(rest) = line.strip_prefix("event:") {
                        event_type = rest.trim().to_string();
                    } else if let Some(rest) = line.strip_prefix("data:") {
                        data = rest.trim().to_string();
                    }
                }
                match event_type.as_str() {
                    "progress" => {
                        let parsed: serde_json::Value =
                            serde_json::from_str(&data).unwrap_or(serde_json::json!({}));
                        let phase = parsed.get("phase").and_then(|v| v.as_str()).unwrap_or("?");
                        let extra = parsed
                            .get("extra")
                            .map(|v| v.to_string())
                            .unwrap_or_default();
                        println!("  [{}] {} {}", key, phase, extra);
                    }
                    "done" => {
                        println!("  ✅ {} upgrade complete.", key);
                        return Ok(());
                    }
                    "error" => {
                        anyhow::bail!("{}: {}", key, data);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    } else {
        let mut found = false;
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let status_path = format!("/v1/captain/upgrade-status/{}", urlencode(key));
            if let Ok((st, _)) = client.get(&status_path).await {
                if st.is_success() {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            println!(
                "  (no progress data for {} - upgrade may still be starting)",
                key
            );
            return Ok(());
        }
        let terminal = ["complete", "aborted", "rolled_back"];
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let status_path = format!("/v1/captain/upgrade-status/{}", urlencode(key));
            let (st, body) = match client.get(&status_path).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !st.is_success() {
                continue;
            }
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));
            let phase = parsed.get("phase").and_then(|v| v.as_str()).unwrap_or("?");
            println!("  [{}] {}", key, phase);
            if terminal.contains(&phase) {
                match phase {
                    "complete" => println!("  ✅ {} upgrade complete.", key),
                    "aborted" => anyhow::bail!("{} upgrade aborted", key),
                    "rolled_back" => anyhow::bail!("{} upgrade rolled back", key),
                    _ => {}
                }
                break;
            }
        }
        Ok(())
    }
}

/// Start captain in the background.
async fn start_captain_server(
    local_ip: &Option<String>,
    catalog_paths: &Option<String>,
) -> anyhow::Result<()> {
    if let Some(pid) = find_captain_pid() {
        anyhow::bail!("captain is already running (pid {pid})");
    }

    let binary = find_captain_binary();
    if !binary.exists() {
        anyhow::bail!(
            "captain binary not found at {}. Run 'cargo build -p captain --release' first.",
            binary.display()
        );
    }

    let log_dir = std::env::var("SENTIN8_LOG_DIR").unwrap_or_else(|_| ".run/logs".to_string());
    let _ = std::fs::create_dir_all(&log_dir);

    let captain_log = std::path::Path::new(&log_dir).join("captain.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&captain_log)?;

    let prefix_env = std::env::var("SENTIN8_CAPTAIN_BINARY_PREFIX")
        .unwrap_or_else(|_| "target/release".to_string());

    // Resolve the local IP - auto-detect if not provided.
    let resolved_ip = match local_ip {
        Some(ip) => ip.clone(),
        None => auto_detect_local_ip().ok_or_else(|| {
            anyhow::anyhow!("Could not auto-detect a routable IP. Pass --local-ip <IP> explicitly.")
        })?,
    };

    let mut cmd = std::process::Command::new(&binary);
    cmd.env("SENTIN8_CAPTAIN_BINARY_PREFIX", &prefix_env)
        .env("SENTIN8_CAPTAIN_LOCAL_IP", &resolved_ip)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file));

    // Spawn captain in its own process group (new session via setsid)
    // so that killing the CLI (timeout, Ctrl+C) does NOT kill captain
    // and its managed services. Without this, SIGTERM to the CLI
    // propagates to all children in the same process group.
    unsafe {
        cmd.pre_exec(|| {
            setsid();
            Ok(())
        });
    }

    // Pass catalog paths so captain can load external service catalogs.
    if let Some(paths) = catalog_paths {
        cmd.env("SENTIN8_CAPTAIN_CATALOG_PATHS", paths);
    }
    // Pass the log dir so captain redirects child service logs there too.
    cmd.env("SENTIN8_LOG_DIR", &log_dir);
    // Pass the local secret-reference store root (architecture §4.4) so
    // captain propagates it to child services - they resolve
    // `sentin8-secrets://` URIs against this dir (fdx provider tokens, …).
    if let Ok(secrets_dir) = std::env::var("SENTIN8_SECRETS_DIR") {
        cmd.env("SENTIN8_SECRETS_DIR", secrets_dir);
    }
    // Pass the M2M DCR file-cache root - the AUTHORITATIVE DCR credential
    // load path (crates/auth/m2m). Default is /etc/sentin8/m2m-credentials,
    // unwritable in dev (root-owned), which disables the cache and forces a
    // full DCR dance on EVERY boot (incident 2026-09-22: cold-boot DCR
    // storms + retry-window exhaustion). Derive it from the secrets dir so
    // dev and prod both get a writable cache by default.
    let m2m_dir = std::env::var("SENTIN8_M2M_CREDENTIALS_DIR").unwrap_or_else(|_| {
        let secrets =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
        format!("{secrets}/m2m-credentials")
    });
    cmd.env("SENTIN8_M2M_CREDENTIALS_DIR", &m2m_dir);

    // Certificate-bound M2M identity (auth design §4.3c target state): the
    // PUBLIC Acme Root-CA cert for outbound DCR/token channels and the
    // optional client-auth CA for service TLS listeners.
    //
    // SECURITY: only the `.crt` path travels - NEVER `SENTIN8_ACME_DATA_DIR`
    // itself. That dir holds the Root/Intermediate CA PRIVATE keys
    // (`root-ca.key`, `intermediate-ca.key`); putting the dir path into every
    // service's environment would let any compromised service read them and
    // forge the entire platform identity chain, defeating the DCR cert gate.
    // Workloads reach Acme's public APIs over HTTPS, never its files.
    let acme_dir = std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/.sentin8/acme")
    });
    let root_ca = format!("{acme_dir}/ca/root-ca.crt");
    if std::env::var("SENTIN8_TLS_CA_PEM").is_err() {
        cmd.env("SENTIN8_TLS_CA_PEM", &root_ca);
    }
    if std::env::var("SENTIN8_TLS_CLIENT_CA_PEM").is_err() {
        cmd.env("SENTIN8_TLS_CLIENT_CA_PEM", &root_ca);
    }

    let child = cmd.spawn()?;

    let pid = child.id();
    println!("captain started (pid {pid})");
    println!("  Local IP: {resolved_ip}");
    println!("  Logs: {}", captain_log.display());
    println!(
        "  API:  http://localhost:{}",
        sentin8::config::captain_port()
    );
    std::mem::forget(child);

    // Stream startup progress via SSE until the platform is ready.
    stream_startup().await;

    Ok(())
}

/// Stop captain gracefully via the shutdown API endpoint.
/// This triggers a full graceful shutdown: captain stops all managed
/// services, releases the advisory lock, and exits.
///
/// Identity : the shutdown endpoint is Shield-gated on
/// `sentin8:captain:admin` - the CLI attaches the signed-in operator's
/// token (device flow, cached credentials) when one is available. When
/// `allow_fallback` is set (pre-scout bootstrap/CI window, Auth not up),
/// auth failure falls back to SIGTERM so bootstrap/CI stop paths still
/// work. Post-bootstrap the caller passes `false` (DEVUI-1.3) - a signed-
/// out or denied stop fails instead of tearing the platform down.
///
/// `via_uds` (§6.1.2): the request goes over the local control socket,
/// where the kernel-proven peer uid authorizes it - no token needed.
async fn stop_captain_server(via_uds: bool, allow_fallback: bool) -> anyhow::Result<()> {
    let pid = find_captain_pid().ok_or_else(|| anyhow::anyhow!("captain is not running"))?;

    println!("Requesting graceful shutdown from captain (pid {pid})...");
    println!("  captain will stop all managed services before exiting.");

    // Resolve the shutdown request over the selected transport. Uniform
    // result: Ok((status, body)) on an HTTP exchange, Err(detail) on a
    // transport failure. (The gated handler once returned HTTP 200 with an
    // {"error": …} body on auth failure - accepting any 2xx made the CLI
    // wait forever for a shutdown that never happened; incident 2026-09-08.
    // Hence the status is kept and the body always inspected.)
    let resp: Result<(reqwest::StatusCode, String), String> = if via_uds {
        let transport = CaptainTransport::resolve();
        let CaptainTransport::Unix { socket_path } = transport else {
            anyhow::bail!("internal: via_uds set but transport is TCP");
        };
        let client = UdsClient::new(socket_path);
        match client
            .request(hyper::Method::POST, "/v1/captain/shutdown", None)
            .await
        {
            Ok((st, body)) => Ok((
                reqwest::StatusCode::from_u16(st.as_u16())
                    .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                String::from_utf8_lossy(&body).into_owned(),
            )),
            Err(e) => Err(format!("{e:#}")),
        }
    } else {
        let base = captain_url();
        let http = reqwest::Client::new();
        // Attach the signed-in operator's token - best-effort: without it the
        // gated endpoint rejects and the SIGTERM fallback runs below.
        let req = attach_operator_token(
            http.post(format!(
                "{}/v1/captain/shutdown",
                base.trim_end_matches('/')
            ))
            .timeout(std::time::Duration::from_secs(10)),
        );
        match req.send().await {
            Ok(r) => {
                let status = r.status();
                match r.text().await {
                    Ok(body) => Ok((status, body)),
                    Err(e) => Err(format!("body read failed: {e}")),
                }
            }
            Err(e) => Err(format!("{e}")),
        }
    };

    match resp {
        Ok((status, body)) if status.is_success() => {
            let accepted = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|b| {
                    b.get("status")
                        .and_then(|s| s.as_str())
                        .map(|s| s == "shutting_down")
                })
                .unwrap_or(false);
            if accepted {
                println!("Shutdown request accepted.");
            } else {
                if !allow_fallback {
                    anyhow::bail!(
                        "shutdown rejected - signed-in operator with `sentin8:captain:admin` required. \
                         Run `sentin8-cli signin` and retry."
                    );
                }
                println!("shutdown rejected (unexpected response) - falling back to SIGTERM.");
                unsafe { libc_kill(pid, 15) };
            }
        }
        Ok((status, _)) => {
            if !allow_fallback {
                anyhow::bail!(
                    "shutdown rejected (HTTP {}) - signed-in operator with \
                     `sentin8:captain:admin` required. Run `sentin8-cli signin` and retry.",
                    status
                );
            }
            println!(
                "shutdown rejected (HTTP {}) - falling back to SIGTERM.",
                status
            );
            unsafe { libc_kill(pid, 15) };
        }
        Err(e) => {
            if !allow_fallback {
                anyhow::bail!(
                    "captain API unreachable ({e}) - signed-in operator required once \
                     the platform is bootstrapped. Run `sentin8-cli signin` and retry."
                );
            }
            // Fallback: if the API is unreachable, try SIGTERM as a last resort.
            println!("API unreachable ({e}) - falling back to SIGTERM.");
            unsafe { libc_kill(pid, 15) };
        }
    }

    // Stream shutdown progress via SSE while waiting for captain to exit.
    stream_shutdown().await;

    // Final check - if captain is still alive after SSE, wait then SIGKILL.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if !pid_alive(pid) {
            println!("captain stopped.");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    if pid_alive(pid) {
        println!("captain did not exit - sending SIGKILL.");
        unsafe { libc_kill(pid, 9) };
        println!("captain killed.");
    } else {
        println!("captain stopped.");
    }
    Ok(())
}

/// Kill orphaned service processes that captain is no longer tracking.
///
/// When captain crashes or is SIGKILLed, its child services become orphans.
/// This scans for any `target/(release|debug)/` binary processes and kills
/// them (SIGTERM, wait 1s, SIGKILL). The pattern matches any service binary
/// in the target directory - both platform (sentin8-*) and vertical
/// (e.g. bank8-*, hotel8-*) - without hardcoding vertical names.
fn kill_orphan_processes() {
    let me = std::process::id();
    let pids: Vec<u32> = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("target/(release|debug)/[^/]+$")
        .output()
        .ok()
        .into_iter()
        .filter(|o| o.status.success())
        .flat_map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter_map(|s| s.parse::<u32>().ok())
        .filter(|p| *p != me)
        .collect();

    if pids.is_empty() {
        return;
    }

    println!("Killing orphaned service processes: {pids:?}");

    // SIGTERM first.
    for pid in &pids {
        unsafe { libc_kill(*pid, 15) };
    }
    std::thread::sleep(std::time::Duration::from_secs(1));

    // SIGKILL any survivors.
    for pid in &pids {
        if pid_alive(*pid) {
            unsafe { libc_kill(*pid, 9) };
        }
    }
}

/// Flush stale `captain:svc:*` keys from Valkey so they don't confuse the next
/// captain start. Uses the `VALKEY_URL` env var (or the default
/// `valkey://localhost:6379/0`).
fn flush_valkey_service_registry() {
    let valkey_url = std::env::var("VALKEY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(sentin8::config::service_valkey_url);

    // Use valkey-cli via docker exec (the Valkey is in a container).
    let keys_output = std::process::Command::new("docker")
        .args([
            "exec",
            "sentin8-valkey",
            "valkey-cli",
            "--scan",
            "--pattern",
            "captain:svc:*",
        ])
        .output();

    let keys: Vec<String> = match keys_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => return, // Valkey not in container or unreachable - skip.
    };

    if keys.is_empty() {
        return;
    }

    for key in &keys {
        let _ = std::process::Command::new("docker")
            .args(["exec", "sentin8-valkey", "valkey-cli", "DEL", key])
            .output();
    }
    println!(
        "Flushed {} stale captain:svc:* entries from Valkey.",
        keys.len()
    );

    let _ = valkey_url; // suppressed unused warning - valkey_url used for future direct connection
}

/// Print a single-line status update that overwrites the previous line.
///
/// Uses `\x1b[2K` (ANSI clear entire line) + `\r` (carriage return) to
/// cleanly erase any previous content, then truncates the message to
/// the terminal width so long lines don't wrap. Flushes stdout.
fn print_line(msg: &str) {
    use std::io::Write;
    // Get terminal width (fallback to 80 if not a TTY).
    let width = terminal_width().unwrap_or(80);
    // Truncate to terminal width (count chars, not bytes - emoji are
    // multi-byte but display as 1-2 columns; this is approximate).
    let truncated: String = msg.chars().take(width.saturating_sub(1)).collect();
    // \x1b[2K = clear entire line, \r = move to column 1.
    print!("\x1b[2K\r{truncated}");
    let _ = std::io::stdout().flush();
}

/// Get the terminal width from the TIOCGWINSZ ioctl (Unix only).
fn terminal_width() -> Option<usize> {
    // Use libc::ioctl with TIOCGWINSZ to get the window size.
    #[repr(C)]
    struct WinSize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    let mut ws = WinSize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // TIOCGWINSZ value - 0x5413 on Linux.
    const TIOCGWINSZ: u64 = 0x5413;
    let ret = unsafe { libc_ioctl(1, TIOCGWINSZ as _, &mut ws as *mut _ as *mut _) };
    if ret == 0 && ws.ws_col > 0 {
        Some(ws.ws_col as usize)
    } else {
        None
    }
}

extern "C" {
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}
unsafe fn libc_ioctl(
    fd: std::ffi::c_int,
    request: std::ffi::c_ulong,
    arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    ioctl(fd, request, arg)
}

/// Stream startup progress from captain's SSE endpoint.
/// Waits for the API to become available (up to 10s), then streams
/// progress events until the platform is ready or times out.
///
/// Transport-aware (§6.1.2): over the local control socket the stream is
/// authorized by peer credentials, so signed-out `make start` regains the
/// live startup feed.
/// Environment variables passed to the successor captain (SELFUP-1.6).
/// Everything else the old process had (RUST_LOG, PATH, …) is NOT carried
/// over - the takeover env is the deliberate, inspectable platform config.
const TAKEOVER_ENV_PREFIXES: &[&str] = &["SENTIN8_", "RUST_LOG"];
const TAKEOVER_ENV_EXACT: &[&str] = &["DATABASE_URL", "VALKEY_URL"];

/// Read the running captain's environment from /proc/{pid}/environ and
/// filter to the takeover set (SENTIN8_*, RUST_LOG, DATABASE_URL, VALKEY_URL).
/// This is how the successor boots with the ORIGINAL --catalog-paths /
/// BINARY_PREFIX regardless of how the CLI was invoked (design §4.8b-3).
fn capture_takeover_env(pid: u32) -> anyhow::Result<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/environ"))
        .map_err(|e| anyhow::anyhow!("read /proc/{pid}/environ: {e}"))?;
    let mut env: Vec<(String, String)> = raw
        .split('\0')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| {
            TAKEOVER_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
                || TAKEOVER_ENV_EXACT.iter().any(|e| k == e)
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    env.sort();
    Ok(env)
}

/// Zero-downtime captain-only restart (SELFUP-1.6, design §4.8b-3).
///
/// SIGTERM the running captain PROCESS ONLY - its signal path exits without
/// touching managed services - then spawn the successor with the takeover
/// environment captured from /proc. The successor's boot sweep (§4.8b-2)
/// adopts the untouched fleet, so no service is stopped or spawned twice.
/// Requires the local UDS transport: over TCP (remote captain configured)
/// there is no local supervisor to signal, and peer credentials prove
/// nothing across hosts.
async fn upgrade_self() -> anyhow::Result<()> {
    let transport = CaptainTransport::resolve();
    if !transport.is_local_socket() {
        anyhow::bail!(
            "upgrade-self requires the local UDS control socket - a remote captain_url \
             is configured, so there is no local supervisor to replace. Run the command \
             on the captain host (design §4.8b-3)."
        );
    }

    let pid = find_captain_pid()
        .ok_or_else(|| anyhow::anyhow!("captain is not running - nothing to upgrade"))?;

    // Pre-flight: the successor binary MUST exist before we signal - never
    // kill the supervisor without a replacement ready.
    let binary = find_captain_binary();
    if !binary.exists() {
        anyhow::bail!(
            "successor binary not found at {}. Build it first \
             (make build-rust); refusing to kill captain without a replacement.",
            binary.display()
        );
    }

    // Pre-flight: capture the takeover environment from the LIVE process.
    let takeover_env = capture_takeover_env(pid)?;
    println!("Captain upgrade-self (pid {pid})");
    println!("  successor binary: {}", binary.display());
    println!("  takeover env: {} variable(s)", takeover_env.len());
    for (k, v) in takeover_env.iter().take(6) {
        println!(
            "    {k}={}",
            if k.contains("PASSWORD") || k.contains("TOKEN") {
                "***"
            } else {
                v
            }
        );
    }
    if takeover_env.len() > 6 {
        println!("    … {} more", takeover_env.len() - 6);
    }

    // 1. SIGTERM the supervisor only. Its signal handler exits immediately
    //    without touching managed services (§4.8b-1 signal path).
    println!("  sending SIGTERM to captain (managed services keep running)…");
    unsafe { libc_kill(pid, 15) };

    // 2. Wait for exit (≤15s, then SIGKILL).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while pid_alive(pid) && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if pid_alive(pid) {
        println!("  captain did not exit - sending SIGKILL.");
        unsafe { libc_kill(pid, 9) };
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    println!("  captain stopped - fleet still serving.");

    // 3. Wait for the management port to free (≤10s) so the successor bind
    //    cannot race the old listener's close.
    let mgmt_port = sentin8::config::captain_port();
    let port_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < port_deadline {
        if tokio::net::TcpListener::bind(("127.0.0.1", mgmt_port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // 4. Spawn the successor with the captured takeover env (setsid - same
    //    isolation as start_captain_server so killing the CLI cannot take
    //    captain down; logs append to the same captain.log).
    let log_dir = std::env::var("SENTIN8_LOG_DIR").unwrap_or_else(|_| ".run/logs".to_string());
    let _ = std::fs::create_dir_all(&log_dir);
    let captain_log = std::path::Path::new(&log_dir).join("captain.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&captain_log)?;

    let mut cmd = std::process::Command::new(&binary);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file));
    for (k, v) in &takeover_env {
        cmd.env(k, v);
    }
    unsafe {
        cmd.pre_exec(|| {
            setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn successor captain: {e}"))?;
    let new_pid = child.id();
    std::mem::forget(child);
    println!("  successor captain started (pid {new_pid})");

    // 5. Stream startup progress (SSE) until the platform reports ready -
    //    the transport re-resolves to the UDS once the successor binds it.
    stream_startup().await;
    Ok(())
}

async fn stream_startup() {
    // Wait for the API to become available (captain just spawned).
    let api_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    // Connect loop - the only exits are return (auth-rejected / deadline)
    // or `break 'connect stream` once the API answers. The transport is
    // RE-RESOLVED per attempt: right after `make start` the UDS socket
    // does not exist yet (captain is still booting) - once it appears the
    // stream flips to the peer-cred-authorized socket automatically.
    let mut stream = 'connect: loop {
        if std::time::Instant::now() >= api_deadline {
            println!("  (API not reachable - use 'make status' to check manually)");
            return;
        }
        let transport = CaptainTransport::resolve();
        match sse_connect(&transport, "/v1/captain/startup-stream").await {
            Ok(src) => break 'connect src,
            Err(SseError::AuthRejected) => {
                // Only report the sign-in hint when no local socket exists:
                // with a reachable socket the peer credentials authorize the
                // stream, so AuthRejected cannot be about sign-in.
                if !transport.is_local_socket() {
                    println!("  (startup stream requires sign-in - 'sentin8 signin'; use 'make status' to check)");
                    return;
                }
                println!(
                    "  (startup stream rejected over local socket - use 'make status' to check)"
                );
                return;
            }
            Err(SseError::Transport(_)) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await
            }
        }
    };

    // Wall-clock cap - a stalled startup stream must not hang `make start`
    // forever; captain's own readiness is monitored separately (incident
    // 2026-09-08).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while let Some(chunk) = tokio::select! {
        c = stream.next_chunk() => c,
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
            print_line("  ⏳ Startup stream timed out - use 'make status' to check");
            println!();
            return;
        }
    } {
        let text = String::from_utf8_lossy(&chunk.unwrap_or_default()).to_string();
        for line in text.lines() {
            if line.starts_with("event:") {
                let event = line.strip_prefix("event:").unwrap_or("").trim();
                match event {
                    "progress" => {}
                    "ready" => {
                        // All services are Active - platform is ready.
                        print_line("  ✅ Platform ready");
                        println!();
                    }
                    // a crash-looped service is a FIRST-CLASS
                    // failure - printed loudly with the reason + log path,
                    // never hidden inside a bare 'waiting on' loop.
                    "alert" => {}
                    "done" => {
                        return;
                    }
                    "timeout" => {
                        print_line("  ⏳ Startup timed out - use 'make status' to check");
                        println!();
                        return;
                    }
                    _ => {}
                }
            }
            if line.starts_with("data:") {
                let data = line.strip_prefix("data:").unwrap_or("").trim();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                    // Alert frames carry the failed service + reason + log.
                    if let Some(reason) = parsed["reason"].as_str() {
                        let svc = parsed["service"].as_str().unwrap_or("?");
                        let log = parsed["log_path"].as_str().unwrap_or("");
                        print_line(&format!("  ❌ {svc} FAILED: {reason}\n     → log: {log}"));
                        continue;
                    }
                    let ready = parsed["ready_count"].as_u64().unwrap_or(0);
                    let total = parsed["total"].as_u64().unwrap_or(0);
                    if let Some(pending) = parsed["pending"].as_array() {
                        let names: Vec<&str> = pending
                            .iter()
                            .filter_map(|p| p["service"].as_str())
                            .collect();
                        if !names.is_empty() {
                            let msg = format!(
                                "  ⏳ {ready}/{total} ready - waiting on: {}",
                                names.join(", ")
                            );
                            print_line(&msg);
                        }
                    }
                }
            }
        }
    }
}

/// Stream shutdown progress from captain's SSE endpoint.
/// Streams the number of remaining services until all are stopped.
///
/// Transport-aware (§6.1.2) - see `stream_startup`.
async fn stream_shutdown() {
    let transport = CaptainTransport::resolve();
    // Gated endpoint, but shutdown progress is cosmetic - the CLI's own
    // PID/SIGKILL deadline below is what waits for captain to exit, so a
    // rejected/unavailable stream is just a missing feed.
    let mut stream = match sse_connect(&transport, "/v1/captain/shutdown-stream").await {
        Ok(src) => src,
        Err(_) => {
            // API already down, no token, or rejected - captain exit is
            // monitored separately (PID poll + SIGKILL deadline).
            return;
        }
    };

    // Wall-clock cap: the SSE stream closes on its own when captain exits,
    // but a stalled captain must not hang `make stop` forever - the caller's
    // SIGKILL deadline handles the leftover (incident 2026-09-08).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150);
    while let Some(chunk) = tokio::select! {
        c = stream.next_chunk() => c,
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
            print_line("  ⏳ Shutdown stream timed out (captain exit monitored separately)");
            println!();
            return;
        }
    } {
        let text = String::from_utf8_lossy(&chunk.unwrap_or_default()).to_string();
        for line in text.lines() {
            if line.starts_with("event:") {
                let event = line.strip_prefix("event:").unwrap_or("").trim();
                if event == "done" {
                    print_line("  ✅ All services stopped");
                    println!();
                    return;
                }
                if event == "timeout" {
                    print_line("  ⏳ Shutdown timed out");
                    println!();
                    return;
                }
            }
            if line.starts_with("data:") {
                let data = line.strip_prefix("data:").unwrap_or("").trim();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                    let remaining = parsed["remaining"].as_u64().unwrap_or(0);
                    let total = parsed["total"].as_u64().unwrap_or(0);
                    let stopped = parsed["stopped"].as_array().map(|a| a.len()).unwrap_or(0);
                    let msg = format!("  ⏳ {stopped}/{total} stopped, {remaining} remaining");
                    print_line(&msg);
                }
            }
        }
    }
}

pub async fn run(cmd: CaptainCommand) -> anyhow::Result<()> {
    // Transport selection (DEVUI-2.1): local UDS control socket when no
    // remote URL is configured and the socket file exists - signed-out
    // `make start/stop/status` work as root/socket-owner. Otherwise TCP.
    let transport = CaptainTransport::resolve();
    match cmd {
        // ── Platform-level commands (no HTTP API needed) ─────────────
        CaptainCommand::Start {
            local_ip,
            catalog_paths,
            services,
        } => {
            // the scope argument is ONE comma-joined string
            // (every group Makefile passes its pin this way) - parsed by
            // [`parse_scope_list`]. An empty result (argument absent or only
            // separators) means the platform-core default - NO explicit
            // allow-list, so the spawned captain boots by its
            // unset-`SENTIN8_SERVICES` default (platform-only)
            // with no env var exported.
            let scope_list = parse_scope_list(services.as_deref());
            if scope_list.is_empty() {
                // DEVUI-1.3 - spawning the supervisor is platform lifecycle:
                // post-bootstrap it requires the signed-in operator - unless
                // this CLI can reach captain via the local control socket
                // (§6.1.2). The socket cannot pre-exist when captain is down
                // (the spawned captain creates it; the caller is by
                // definition on this machine), so the spawn gate keys on
                // `local_control_possible`, not the current transport.
                if platform_bootstrapped() && !CaptainTransport::local_control_possible() {
                    require_signed_in("captain start", &transport)?;
                }
                return start_captain_server(&local_ip, &catalog_paths).await;
            }
            // Start specific services. Captain up → the start-services API
            // (idempotent). Captain down → COLD BOOT with the argument as
            // the boot allow-list (captain DESIGN §3): the
            // API is not listening yet, so the services argument is passed
            // to the spawned captain via `SENTIN8_SERVICES` instead of
            // being silently dropped. Both paths resolve the types through
            // the same catalog union the captain loads.
            if captain_up() {
                let client = captain_api_client(&transport);
                let (status, body) = client
                    .post_json(
                        "/v1/captain/start-services",
                        serde_json::json!({"service_types": scope_list}),
                    )
                    .await?;
                let parsed: serde_json::Value = if status.is_success() {
                    serde_json::from_slice(&body)?
                } else {
                    anyhow::bail!(
                        "captain API error: {} {}",
                        status,
                        String::from_utf8_lossy(&body)
                    );
                };
                let started = parsed
                    .get("started_services")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                println!("Started {} services:", started.len());
                for svc in &started {
                    if let Some(name) = svc.as_str() {
                        println!("  → {} started", name);
                    }
                }
                return Ok(());
            }
            // Cold boot with an explicit scope : the typed
            // tokens re-join into the boot allow-list for the spawned
            // captain (DESIGN §4.1 - the join is the serialized form, not
            // the identity of a single type).
            if platform_bootstrapped() && !CaptainTransport::local_control_possible() {
                require_signed_in("captain start", &transport)?;
            }
            let scope = scope_list.join(",");
            std::env::set_var("SENTIN8_SERVICES", &scope);
            println!("→ captain down - cold boot with explicit scope ({scope}); captain start");
            return start_captain_server(&local_ip, &catalog_paths).await;
        }

        CaptainCommand::Stop => {
            // DEVUI-1.3 - post-bootstrap, stop must not fall back to a bare
            // SIGTERM when the gated endpoint rejects: fail instead so a
            // signed-out caller cannot tear the platform down. The fallback
            // inside stop_captain_server only engages pre-scout (bootstrap/CI,
            // Auth not up). The sign-in gate is skipped on the local-socket
            // transport (§6.1.2 - kernel-proven peer credentials).
            let signed_in = if platform_bootstrapped() {
                require_signed_in("captain stop", &transport).is_ok()
            } else {
                true
            };
            stop_captain_server(transport.is_local_socket(), signed_in).await?;
            kill_orphan_processes();
            flush_valkey_service_registry();
            return Ok(());
        }

        CaptainCommand::Restart {
            local_ip,
            catalog_paths,
        } => {
            if find_captain_pid().is_some() {
                let signed_in = if platform_bootstrapped() {
                    require_signed_in("captain restart", &transport).is_ok()
                } else {
                    true
                };
                stop_captain_server(transport.is_local_socket(), signed_in).await?;
                kill_orphan_processes();
                flush_valkey_service_registry();
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if platform_bootstrapped() && !CaptainTransport::local_control_possible() {
                require_signed_in("captain restart", &transport)?;
            }
            return start_captain_server(&local_ip, &catalog_paths).await;
        }

        CaptainCommand::UpgradeSelf => {
            // SELFUP-1.6 (design §4.8b-3): zero-downtime supervisor swap.
            // No sign-in gate - UDS SO_PEERCRED is the authorization, and
            // the pre-flight + signal path needs no management API.
            return upgrade_self().await;
        }

        // ── HTTP API commands ────────────────────────────────────────
        _ => {
            let client = captain_api_client(&transport);

            match cmd {
                CaptainCommand::Services {
                    r#type,
                    status,
                    ip,
                    no_infra,
                } => {
                    let mut path = "/v1/captain/services".to_string();
                    let mut params = Vec::new();
                    if let Some(t) = &r#type {
                        params.push(format!("service_type={}", urlencode(t)));
                    }
                    if let Some(s) = &status {
                        params.push(format!("status={}", urlencode(s)));
                    }
                    if let Some(i) = &ip {
                        params.push(format!("local_ip={}", urlencode(i)));
                    }
                    if !params.is_empty() {
                        path.push('?');
                        path.push_str(&params.join("&"));
                    }

                    let (status_code, body) = client.get(&path).await?;
                    if !status_code.is_success() {
                        anyhow::bail!(
                            "captain API error: {} {}",
                            status_code,
                            String::from_utf8_lossy(&body)
                        );
                    }

                    let instances: Vec<ServiceInstance> = serde_json::from_slice(&body)?;

                    if instances.is_empty() {
                        println!("No service instances found.");
                        return Ok(());
                    }

                    // Infrastructure summary (PostgreSQL + Valkey). Best-effort
                    // - each backend degrades to a one-line "unreachable"
                    // line if it's down, so `make status` never aborts.
                    // Printed above the service table so the backing-database
                    // health is the first thing visible.
                    if !no_infra {
                        println!();
                        crate::infra::print_infra().await;
                    }

                    // Machines summary - group instances by local_ip and
                    // aggregate per-machine totals. Printed after the
                    // Infrastructure block so the reader sees which machine
                    // hosts what before the per-service detail.
                    let machines = fetch_machines(&client).await;
                    print_machines(&instances, &machines);

                    let mut instances = instances;
                    instances.sort_by(|a, b| {
                        a.service_type
                            .cmp(&b.service_type)
                            .then_with(|| a.key.cmp(&b.key))
                    });

                    println!(
                        "{:<23} {:<7} {:<4} {:<4} {:<6} {:<6} {:<8} {:<6} {:<8} {:<10} {:<16} {:<22} {:<8}",
                        "SERVICE", "CALLS", "RST", "ERR", "WRN", "CPU%", "MEM", "LAT", "UPTIME", "STATUS", "VERSION", "KEY", "PID"
                    );
                    println!(
                        "{:<23} {:<7} {:<4} {:<4} {:<6} {:<6} {:<8} {:<6} {:<8} {:<10} {:<16} {:<22} {:<8}",
                        "-------", "-----", "---", "---", "---", "----", "------", "---", "------", "------", "-------", "---", "---"
                    );
                    for inst in &instances {
                        // CAPTAIN-4: `{version}.{build_hash}` when both are
                        // captured from the health endpoint.
                        // CAPTAIN-10: dev builds fall back to the crate
                        // version for the hash (`SENTIN8_BUILD_HASH` unset -
                        // packaging sets it), so the pair would render as a
                        // duplicated `0.1.0.0.1.0`. When build == version the
                        // build is shown alone (the operator still sees WHICH
                        // version runs; the packaged `{version}.{build}` form
                        // only adds information when it differs).
                        // with the git-hash stamp the health
                        // `version` field is the FULL identity
                        // (`0.3.0+5f3a9c1.d`) and `build` is the raw hash -
                        // collapse ALSO when `build` is already contained in
                        // `version` (the hash part / bare-version fallback
                        // the unstamped case produces), so a stamped row
                        // shows exactly `0.3.0+5f3a9c1.d` rather than
                        // `0.3.0+5f3a9c1.d.0.3.0`.
                        let ver = if inst.version.is_empty() {
                            String::new()
                        } else if inst.build_hash.is_empty()
                            || inst.build_hash == inst.version
                            || inst.version.contains(&inst.build_hash)
                        {
                            inst.version.clone()
                        } else {
                            format!("{}.{}", inst.version, inst.build_hash)
                        };
                        let uptime = inst
                            .started_at
                            .map(|ts| {
                                let secs = chrono::Utc::now().timestamp() - ts;
                                if secs < 0 {
                                    return "0s".into();
                                }
                                let d = secs / 86400;
                                let h = (secs % 86400) / 3600;
                                let m = (secs % 3600) / 60;
                                let s = secs % 60;
                                // Drop seconds once uptime reaches 1 hour.
                                if d > 0 {
                                    format!("{}d{}h", d, h)
                                } else if h > 0 {
                                    format!("{}h{}m", h, m)
                                } else if m > 0 {
                                    format!("{}m{}s", m, s)
                                } else {
                                    format!("{}s", s)
                                }
                            })
                            .unwrap_or_default();
                        let mem_str = if inst.rss_mb_avg_1m >= 1024.0 {
                            format!("{:.1} GB", inst.rss_mb_avg_1m / 1024.0)
                        } else {
                            format!("{:.0} MB", inst.rss_mb_avg_1m)
                        };
                        println!(
                            "{:<23} {:<7} {:<4} {:<4} {:<6} {:<6.1} {:<8} {:<6.1} {:<8} {:<10} {:<16} {:<22} {:<8}",
                            inst.service_type,
                            inst.api_calls,
                            inst.restarts,
                            inst.errors,
                            inst.warnings,
                            inst.cpu_avg_1m,
                            mem_str,
                            inst.latency_avg_1m_ms,
                            uptime,
                            inst.status,
                            ver,
                            inst.key,
                            inst.pid,
                        );
                    }

                    // Manual intervention required : fetch the give-up
                    // alert list and print it AFTER the instance table - a
                    // parked service appears in NEITHER view (its registry row
                    // is deleted at give-up), so without this block a failed
                    // service was only visible via `make start`'s stream or by
                    // grep through captain.log. Best-effort: an alerts-fetch
                    // failure never breaks the status output.
                    let alerts: Vec<CaptainAlert> = match client.get("/v1/captain/alerts").await {
                        Ok((code, body)) if code.is_success() => {
                            serde_json::from_slice(&body).unwrap_or_default()
                        }
                        _ => Vec::new(),
                    };
                    if !alerts.is_empty() {
                        println!();
                        println!(
                            "❌ MANUAL INTERVENTION REQUIRED - {} service(s) gave up after max restarts:",
                            alerts.len()
                        );
                        for a in &alerts {
                            let age = if a.at > 0 {
                                let s = chrono::Utc::now().timestamp() - a.at;
                                if s > 0 {
                                    format!("{}m ago", s / 60)
                                } else {
                                    "just now".to_string()
                                }
                            } else {
                                String::new()
                            };
                            let age_suffix = if age.is_empty() {
                                String::new()
                            } else {
                                format!(" ({age})")
                            };
                            println!(
                                "   • {} - {}{}\n       → log: {}",
                                a.service, a.reason, age_suffix, a.log_path
                            );
                        }
                    }
                    println!("\n{} instance(s)", instances.len());
                }

                CaptainCommand::Catalog => {
                    let (status_code, body) = client.get("/v1/captain/catalog").await?;
                    if !status_code.is_success() {
                        anyhow::bail!(
                            "captain API error: {} {}",
                            status_code,
                            String::from_utf8_lossy(&body)
                        );
                    }

                    let entries: Vec<CatalogEntry> = serde_json::from_slice(&body)?;

                    if entries.is_empty() {
                        println!("Catalog is empty.");
                        return Ok(());
                    }

                    let mut entries = entries;
                    entries.sort_by(|a, b| {
                        a.start_priority
                            .cmp(&b.start_priority)
                            .then_with(|| a.service_type.cmp(&b.service_type))
                    });

                    println!(
                        "{:<23} {:<10} {:<8} {:<8}",
                        "SERVICE", "PRIORITY", "PORT", "TYPE"
                    );
                    println!(
                        "{:<23} {:<10} {:<8} {:<8}",
                        "-------", "--------", "----", "----"
                    );
                    for e in &entries {
                        let port_str = if e.fixed_port > 0 {
                            format!("{}", e.fixed_port)
                        } else {
                            "auto".to_string()
                        };
                        let type_str = if !e.web_root.is_empty() {
                            "app"
                        } else if e.service_type.ends_with("-worker") {
                            "worker"
                        } else {
                            "service"
                        };
                        println!(
                            "{:<23} {:<10} {:<8} {:<8}",
                            e.service_type, e.start_priority, port_str, type_str,
                        );
                    }
                    println!("\n{} catalog entry/entries", entries.len());
                }

                CaptainCommand::RestartInstance { key } => {
                    // SELFUP-1.3 (design §4.8b-1): per-instance actions on the
                    // captain key target the supervisor itself - refused
                    // client-side so the operator gets the correct instruction
                    // even when captain's own guard can't answer.
                    refuse_captain_key(&key, "restart-instance")?;
                    let path = format!("/v1/captain/services/{}", urlencode(&key));
                    let (status_code, body) = client
                        .post_json(&path, serde_json::json!({"action": "restart"}))
                        .await?;
                    if !status_code.is_success() {
                        anyhow::bail!(
                            "captain API error: {} {}",
                            status_code,
                            String::from_utf8_lossy(&body)
                        );
                    }
                    println!("Restart sent for {}", key);
                }

                CaptainCommand::StopInstance { key } => {
                    refuse_captain_key(&key, "stop-instance")?;
                    let path = format!("/v1/captain/services/{}", urlencode(&key));
                    let (status_code, body) = client
                        .post_json(&path, serde_json::json!({"action": "stop"}))
                        .await?;
                    if !status_code.is_success() {
                        anyhow::bail!(
                            "captain API error: {} {}",
                            status_code,
                            String::from_utf8_lossy(&body)
                        );
                    }
                    println!("Stop sent for {}", key);
                }

                CaptainCommand::StartInstance { key } => {
                    refuse_captain_key(&key, "start-instance")?;
                    let path = format!("/v1/captain/services/{}", urlencode(&key));
                    let (status_code, body) = client
                        .post_json(&path, serde_json::json!({"action": "start"}))
                        .await?;
                    if !status_code.is_success() {
                        anyhow::bail!(
                            "captain API error: {} {}",
                            status_code,
                            String::from_utf8_lossy(&body)
                        );
                    }
                    println!("Start sent for {}", key);
                }

                CaptainCommand::UpgradeInstance { keys, poll } => {
                    // Upgrade all keys in parallel.
                    let poll_mode = poll;
                    let tasks: Vec<_> = keys
                        .into_iter()
                        .map(|key| {
                            let client = client.clone();
                            tokio::spawn(async move {
                                let result = upgrade_single_instance(client, &key, poll_mode).await;
                                (key, result)
                            })
                        })
                        .collect();

                    let mut had_error = false;
                    for task in tasks {
                        let (key, result) = task.await.unwrap_or_else(|e| {
                            ("unknown".into(), Err(anyhow::anyhow!("task panicked: {e}")))
                        });
                        if let Err(e) = result {
                            eprintln!("  ❌ {} failed: {}", key, e);
                            had_error = true;
                        }
                    }
                    if had_error {
                        anyhow::bail!("one or more upgrades failed");
                    }
                }

                CaptainCommand::Autoscaler => {
                    return print_autoscaler(&client).await;
                }

                CaptainCommand::AutoscalerApprove { kind, ip, decision } => {
                    if !matches!(kind.as_str(), "provision" | "deprovision") {
                        anyhow::bail!("kind must be \"provision\" or \"deprovision\"");
                    }
                    if !matches!(decision.as_str(), "approve" | "reject") {
                        anyhow::bail!("decision must be \"approve\" or \"reject\"");
                    }
                    return autoscaler_approve(&client, &kind, &ip, &decision).await;
                }

                CaptainCommand::Place { ip, services } => {
                    return place_services_on_machine(&ip, &services).await;
                }

                // Platform commands are handled above - unreachable here.
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

/// Hand-place services on a machine (captain DESIGN §11.4):
/// `POST /v1/captain/instances` on the TARGET machine's captain. The CLI
/// builds a per-machine transport from the IP (the default transport
/// resolution is machine-local - a place call is by definition remote),
/// sends the operator bearer, and reports the placement outcome. A 409
/// carries the target's placement-gate refusal reason.
async fn place_services_on_machine(ip: &str, services: &[String]) -> anyhow::Result<()> {
    if services.is_empty() {
        anyhow::bail!("place requires at least one service type");
    }
    let url = format!(
        "http://{ip}:{}/v1/captain/instances",
        sentin8::config::captain_port()
    );
    let token = crate::auth::get_valid_token_blocking()?;
    let body = serde_json::json!({ "service_types": services });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.as_u16() == 409 {
        anyhow::bail!("target machine {ip} refused the placement (placement gate): {text}");
    }
    if !status.is_success() {
        anyhow::bail!("place returned {status}: {text}");
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or(serde_json::json!({"raw": text}));
    let started = parsed
        .get("started_services")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    if started.is_empty() {
        println!(
            "Nothing started on {ip} (services already running there, or not in its catalog)."
        );
    } else {
        println!("Placed on {ip}: {}", started.join(", "));
    }
    Ok(())
}

/// Print the cluster-autoscaler state (design §4.12): profile, backend,
/// fleet, leader, and pending approval requests (manual profile).
async fn print_autoscaler(client: &CaptainApi) -> anyhow::Result<()> {
    let (status_code, body) = client.get("/v1/captain/autoscaler").await?;
    if !status_code.is_success() {
        anyhow::bail!(
            "captain API error: {} {}",
            status_code,
            String::from_utf8_lossy(&body)
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&body)?;

    let profile = v["profile"].as_str().unwrap_or("?");
    let backend = v["backend"].as_str().unwrap_or("?");
    let fleet = v["fleet_machines"].as_u64().unwrap_or(0);
    let max = v["max_machines"].as_u64().unwrap_or(0);
    let min = v["min_machines"].as_u64().unwrap_or(0);
    let leader = v["leader"].as_str().unwrap_or("");
    let is_leader = v["is_leader"].as_bool().unwrap_or(false);

    println!("Cluster autoscaler (machine auto-provisioning, design §4.12):");
    println!("  Profile:  {profile}");
    println!(
        "  Backend:  {backend}{}",
        if backend == "noop" {
            "  (dry-run - no machine is ever created)"
        } else {
            "  (OpenTofu)"
        }
    );
    println!("  Fleet:    {fleet} machine(s) - max {max}, min {min}");
    println!(
        "  Leader:   {}{}",
        if leader.is_empty() {
            "(none - no captain holds the role)"
        } else {
            leader
        },
        if is_leader { "  (this captain)" } else { "" }
    );

    // Per-machine saturation state.
    if let Some(machines) = v["machines"].as_array() {
        if !machines.is_empty() {
            println!("  Machines:");
            for m in machines {
                let ip = m["ip"].as_str().unwrap_or("?");
                let cpu = m["cpu_pct"].as_f64().unwrap_or(0.0);
                let mem = m["mem_pct"].as_f64().unwrap_or(0.0);
                let saturated = m["saturated"].as_bool().unwrap_or(false);
                let svc = m["saturated_service"].as_str().unwrap_or("");
                println!(
                    "    {ip:<16} cpu {cpu:>5.1}%  mem {mem:>5.1}%{}",
                    if saturated {
                        format!("  ⚠ SATURATED ({svc})")
                    } else {
                        String::new()
                    }
                );
            }
        }
    }

    // Pending requests - the manual-profile approval queue.
    if let Some(pending) = v["pending"].as_array() {
        if pending.is_empty() {
            println!("  Pending:  (none)");
        } else {
            println!("  Pending requests (approve with `sentin8 captain autoscaler-approve ...`):");
            for p in pending {
                let kind = p["kind"].as_str().unwrap_or("?");
                let ip = p["ip"].as_str().unwrap_or("?");
                let svc = p["busy_service"].as_str().unwrap_or("");
                let extra = if svc.is_empty() {
                    String::new()
                } else {
                    format!(" (busy: {svc})")
                };
                println!("    • {kind} - triggered by {ip}{extra}");
            }
        }
    }
    Ok(())
}

/// POST the operator's approve/reject decision for one pending request.
async fn autoscaler_approve(
    client: &CaptainApi,
    kind: &str,
    ip: &str,
    decision: &str,
) -> anyhow::Result<()> {
    let (status_code, body) = client
        .post_json(
            "/v1/captain/autoscaler/approve",
            serde_json::json!({"kind": kind, "ip": ip, "decision": decision}),
        )
        .await?;
    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    if !status_code.is_success() {
        let msg = parsed["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| String::from_utf8_lossy(&body).to_string());
        anyhow::bail!("approve failed ({}): {}", status_code, msg);
    }
    match decision {
        "approve" => match parsed["status"].as_str() {
            Some("provisioned") => println!(
                "  ✅ Machine provisioned: {} (captain bootstrapping via backend)",
                parsed["ip"].as_str().unwrap_or("?")
            ),
            Some("deprovisioned") => println!(
                "  ✅ Machine deprovisioned: {}",
                parsed["ip"].as_str().unwrap_or("?")
            ),
            Some("dry_run") => {
                println!("  ✅ Approved - backend executed (noop = dry-run; nothing was created)")
            }
            _ => println!("  ✅ Executed: {parsed}"),
        },
        _ => println!("  🚫 Rejected: {kind} request for {ip} discarded"),
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.replace('/', "%2F")
        .replace(' ', "%20")
        .replace(':', "%3A")
}

/// Print the Machines summary table - one row per distinct `local_ip`,
/// aggregating the per-service metrics into per-machine totals.
///
/// Printed after the Infrastructure block and before the per-service table
/// so the reader sees which machine hosts what before the detail rows.
///
/// - `SVCS`  - number of service instances on that machine
/// - `CALLS` - sum of `api_calls` across all instances on the machine
/// - `RST`   - sum of `restarts`
/// - `ERR`   - sum of `errors`
/// - `WRN`   - sum of `warnings`
/// - `CPU%`  - sum of per-instance `cpu_avg_1m` (total managed-service CPU
///   footprint on that machine, not whole-host CPU)
/// - `MEM%`  - sum of per-instance `memory_avg_1m` (with total RSS in MB
///   shown in parentheses)
/// - `FREE CPU%` - whole-host idle CPU from `/proc/stat` (100 − host CPU%)
/// - `FREE MEM%` - whole-host available memory from `/proc/meminfo`
fn print_machines(instances: &[ServiceInstance], hosts: &[MachineHost]) {
    use std::collections::BTreeMap;

    // BTreeMap gives us sorted-by-IP output for free.
    let mut by_ip: BTreeMap<String, MachineAgg> = BTreeMap::new();

    for inst in instances {
        let agg = by_ip.entry(inst.local_ip.clone()).or_default();
        agg.svcs += 1;
        agg.calls += inst.api_calls;
        agg.restarts += inst.restarts;
        agg.errors += inst.errors;
        agg.warnings += inst.warnings;
        agg.cpu += inst.cpu_avg_1m;
        agg.mem += inst.memory_avg_1m;
        agg.rss_mb += inst.rss_mb_avg_1m;
    }

    // Index host stats by IP for quick lookup.
    let host_by_ip: BTreeMap<String, &MachineHost> =
        hosts.iter().map(|h| (h.ip.clone(), h)).collect();

    println!("Machines:");
    println!(
        "  {:<15} {:<5} {:<7} {:<4} {:<4} {:<4} {:<6} {:<6} {:<10} {:<9} {:<9}",
        "IP", "SVCS", "CALLS", "RST", "ERR", "WRN", "CPU%", "MEM%", "MEM", "FREE CPU", "FREE MEM",
    );
    println!(
        "  {:<15} {:<5} {:<7} {:<4} {:<4} {:<4} {:<6} {:<6} {:<10} {:<9} {:<9}",
        "---",
        "----",
        "-----",
        "---",
        "---",
        "---",
        "----",
        "-----",
        "---",
        "--------",
        "---------",
    );
    for (ip, a) in &by_ip {
        let host = host_by_ip.get(ip);
        let free_cpu = match host {
            Some(h) => format!("{:.1}%", 100.0 - h.cpu_pct),
            None => "-".to_string(),
        };
        let free_mem = match host {
            Some(h) => format!("{:.1}%", 100.0 - h.mem_pct),
            None => "-".to_string(),
        };
        let mem_mb = if a.rss_mb >= 1024.0 {
            format!("{:.1} GB", a.rss_mb / 1024.0)
        } else {
            format!("{:.0} MB", a.rss_mb)
        };
        println!(
            "  {:<15} {:<5} {:<7} {:<4} {:<4} {:<4} {:<6.1} {:<6.1} {:<10} {:<9} {:<9}",
            ip,
            a.svcs,
            a.calls,
            a.restarts,
            a.errors,
            a.warnings,
            a.cpu,
            a.mem,
            mem_mb,
            free_cpu,
            free_mem,
        );
    }
    println!();
}

/// Fetch host-level machine stats from `GET /v1/captain/machines`.
/// Returns an empty vec if the endpoint is unavailable (older captain).
async fn fetch_machines(client: &CaptainApi) -> Vec<MachineHost> {
    let Ok((st, body)) = client.get("/v1/captain/machines").await else {
        return Vec::new();
    };
    if !st.is_success() {
        return Vec::new();
    }
    serde_json::from_slice(&body).unwrap_or_default()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MachineHost {
    ip: String,
    #[serde(default)]
    cpu_pct: f64,
    #[serde(default)]
    mem_pct: f64,
    #[serde(default)]
    used_mb: f64,
}

#[derive(Default)]
struct MachineAgg {
    svcs: i64,
    calls: i64,
    restarts: i32,
    errors: i64,
    warnings: i64,
    cpu: f32,
    mem: f32,
    rss_mb: f32,
}

#[cfg(test)]
mod scope_tests {
    //! (DESIGN §4.1): the `captain start` scope argument is
    //! ONE comma-joined token string - the group Makefiles pass their
    //! pin this way, so the split/canonicalize contract here
    //! is what keeps the API path (start-services list) and the cold-boot
    //! path (SENTIN8_SERVICES allow-list) both correct.

    use super::parse_scope_list;

    #[test]
    fn comma_joined_string_splits_into_typed_tokens() {
        // The exact shape every group Makefile passes: ONE argument.
        let arg = Some("sentin8:captain,sentin8:acme,sentin8:auth,sentin8:bff");
        assert_eq!(
            parse_scope_list(arg),
            vec![
                "sentin8:captain",
                "sentin8:acme",
                "sentin8:auth",
                "sentin8:bff"
            ]
        );
    }

    #[test]
    fn empty_argument_means_platform_core_default() {
        assert!(parse_scope_list(None).is_empty());
        assert!(parse_scope_list(Some("")).is_empty());
        // Only separators/whitespace → still the default.
        assert!(parse_scope_list(Some(" , , ")).is_empty());
    }

    #[test]
    fn trims_and_drops_empty_segments() {
        assert_eq!(
            parse_scope_list(Some(" sentin8:auth ,,, sentin8:bff, ")),
            vec!["sentin8:auth", "sentin8:bff"]
        );
    }

    #[test]
    fn canonicalizes_legacy_hyphen_and_alias_forms() {
        // `bank8-payments-worker` → `bank8:payments:worker`, `:w` → `:worker`
        assert_eq!(
            parse_scope_list(Some("sentin8-auth,bank8-payments-worker,bank8:ledger:w")),
            vec!["sentin8:auth", "bank8:payments:worker", "bank8:ledger:worker"]
        );
        // Already-canonical tokens pass through untouched.
        assert_eq!(
            parse_scope_list(Some("sentin8:bff")),
            vec!["sentin8:bff"]
        );
    }
}
