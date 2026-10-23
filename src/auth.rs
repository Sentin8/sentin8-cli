// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Device flow authentication - OAuth 2.0 Device Authorization Grant (RFC 8628).

use std::fs;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{credentials_path, sentin8_auth_url, Sentin8Config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub sentin8_auth_url: String,
    pub user: Option<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: Option<String>,
    pub subject_id: String,
    pub scopes: Vec<String>,
    pub org_id: Option<String>,
    pub env_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct DeviceAuthRequest {
    client_id: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct RefreshTokenRequest {
    grant_type: String,
    refresh_token: String,
    client_id: String,
}

/// Initiate the device flow sign-in.
pub async fn signin(
    sentin8_auth_url_override: Option<&str>,
    client_id: &str,
    scope: &str,
) -> anyhow::Result<()> {
    let sentin8_auth_url = sentin8_auth_url_override
        .map(String::from)
        .unwrap_or_else(sentin8_auth_url);
    println!("Authenticating against {sentin8_auth_url}");

    // Discover all available command scopes from the database so the token
    // has the right scopes for every service's admin API. The requested
    // scope is merged with the user's role scopes by the auth server.
    let discovered_scopes = discover_command_scopes().await;
    let full_scope = if discovered_scopes.is_empty() {
        scope.to_string()
    } else {
        format!("{scope} {discovered_scopes}")
    };
    if !discovered_scopes.is_empty() {
        println!("  Requesting scopes: {full_scope}");
    }

    // Step 1: Request device code.
    let resp = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?
        .post(format!("{sentin8_auth_url}/oauth/device"))
        .form(&DeviceAuthRequest {
            client_id: client_id.into(),
            scope: full_scope,
            audience: Some("sentin8".into()),
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("device authorization failed: HTTP {}", resp.status());
    }

    let device: DeviceAuthResponse = resp.json().await?;
    let display_url = device
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device.verification_uri);

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  Visit: {display_url}");
    println!("║  Enter code: {}", device.user_code);
    println!("╚══════════════════════════════════════════════════╝");
    println!(
        "\nWaiting for approval (polling every {}s, expires in {}s)...",
        device.interval, device.expires_in
    );

    // Step 2: Poll for token.
    let poll_interval = Duration::from_secs(device.interval);
    let deadline = std::time::Instant::now() + Duration::from_secs(device.expires_in);
    let http = reqwest::Client::new();
    let token_url = format!("{sentin8_auth_url}/oauth/token");

    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("device code expired");
        }
        tokio::time::sleep(poll_interval).await;

        let resp = http
            .post(&token_url)
            .form(&DeviceTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".into(),
                device_code: device.device_code.clone(),
                client_id: client_id.into(),
            })
            .send()
            .await?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await?;
        if status.is_success() {
            let token: TokenResponse = serde_json::from_value(body)?;
            let expires_at =
                chrono::Utc::now() + chrono::Duration::seconds(token.expires_in as i64);
            let access_token = token.access_token.clone();
            let creds = Credentials {
                access_token: token.access_token,
                refresh_token: token.refresh_token.unwrap_or_default(),
                token_type: token.token_type,
                expires_at,
                sentin8_auth_url: sentin8_auth_url.clone(),
                user: decode_user_info(&access_token),
            };
            save_credentials(&creds)?;
            println!("\n✓ Signed in");
            if let Some(email) = &creds.user.as_ref().and_then(|u| u.email.as_ref()) {
                println!("  User: {email}");
            }
            return Ok(());
        }

        // Check for pending vs error.
        let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
        match error {
            "authorization_pending" | "slow_down" => continue,
            "expired_token" => anyhow::bail!("device code expired"),
            "access_denied" => anyhow::bail!("access denied by user"),
            _ => anyhow::bail!("token error: {}", body),
        }
    }
}

/// Sign up a new user via `POST /v1/sign-up`, then optionally initiate
/// device-flow sign-in so the user gets an OAuth token.
pub async fn signup(
    sentin8_auth_url_override: Option<&str>,
    email: &str,
    password: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    auto_signin: bool,
) -> anyhow::Result<()> {
    let sentin8_auth_url = sentin8_auth_url_override
        .map(String::from)
        .unwrap_or_else(sentin8_auth_url);
    println!("Signing up against {sentin8_auth_url}");

    // Tenant resolution rides the auth URL's own hostname: a sign-up
    // against a tenant host (e.g. the OIDF rig's cert env
    // auth.cert.conformance-local.local.sentin8.dev) must provision the
    // user in THAT tenant, not the System env. The URL host IS the
    // x-sentin8-hostname the TLS layer would stamp on a browser visit.
    let hostname = reqwest::Url::parse(&sentin8_auth_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "auth.ops.sys.local.sentin8.dev".to_string());

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let body = serde_json::json!({
        "email": email,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
    });

    let resp = client
        .post(format!("{sentin8_auth_url}/v1/sign-up"))
        .header("content-type", "application/json")
        .header("x-sentin8-hostname", &hostname)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if status.is_success() {
        println!("✓ Account created: {email}");
    } else if status == reqwest::StatusCode::CONFLICT {
        anyhow::bail!("email already registered: {email}");
    } else {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("signup failed: HTTP {status}: {text}");
    }

    if auto_signin {
        println!("\nInitiating device-flow sign-in...");
        signin(
            Some(&sentin8_auth_url),
            "sentin8-cli",
            "openid profile email offline_access",
        )
        .await?;
    } else {
        println!("\nTo sign in, run: sentin8 signin");
    }

    Ok(())
}

/// Sign out - revoke token and clear credentials.
pub async fn signout() -> anyhow::Result<()> {
    let creds = load_credentials();
    if let Some(creds) = creds {
        let _ = reqwest::Client::new()
            .post(format!("{}/oauth/revoke", creds.sentin8_auth_url))
            .form(&[("token", creds.access_token.as_str())])
            .send()
            .await;
    }
    let path = credentials_path();
    let _ = fs::remove_file(&path);
    println!("✓ Signed out");
    Ok(())
}

/// Show current user, scopes, and expiry.
pub fn whoami() -> anyhow::Result<()> {
    let creds = load_credentials()
        .ok_or_else(|| anyhow::anyhow!("not signed in. Run 'sentin8 signin'."))?;
    if let Some(user) = &creds.user {
        if let Some(email) = &user.email {
            println!("User:    {email}");
        }
        println!("Subject: {}", user.subject_id);
        println!("Scopes:  {}", user.scopes.join(", "));
    } else {
        println!("User:    (token claims not decoded)");
    }
    println!(
        "Expires: {}",
        creds.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    let now = chrono::Utc::now();
    if creds.expires_at <= now {
        println!("Status:  EXPIRED - run 'sentin8 signin' or use a command to auto-refresh");
    } else {
        println!("Status:  active");
    }
    Ok(())
}

/// Load credentials, refreshing if expired. Returns the access token.
pub async fn get_valid_token() -> anyhow::Result<String> {
    let mut creds = load_credentials()
        .ok_or_else(|| anyhow::anyhow!("not signed in. Run 'sentin8 signin' to authenticate."))?;
    let now = chrono::Utc::now();
    if creds.expires_at <= now {
        // Try refresh.
        match refresh_token(&mut creds).await {
            Ok(()) => {}
            Err(e) => {
                anyhow::bail!("token expired and refresh failed: {e}. Run 'sentin8 signin'.");
            }
        }
    }
    Ok(creds.access_token)
}

/// Blocking variant of [`get_valid_token`] for call sites that cannot await
/// (reqwest `RequestBuilder` middleware-style wrapping). Uses
/// `block_in_place` inside the multi-threaded tokio runtime; on a
/// current-thread runtime it reads cached credentials without refreshing
/// (best-effort attach - an expired token just gets rejected by the
/// endpoint and the caller degrades gracefully).
pub fn get_valid_token_blocking() -> anyhow::Result<String> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(get_valid_token())),
        Err(_) => {
            // No runtime in scope (e.g. sync CLI path) - cache read only.
            load_credentials()
                .map(|c| c.access_token)
                .ok_or_else(|| anyhow::anyhow!("not signed in"))
        }
    }
}

/// Refresh the access token using the refresh token.
async fn refresh_token(creds: &mut Credentials) -> anyhow::Result<()> {
    if creds.refresh_token.is_empty() {
        anyhow::bail!("no refresh token available");
    }
    let client_id = Sentin8Config::load()
        .client_id
        .unwrap_or_else(|| "sentin8-cli".into());
    let resp = reqwest::Client::new()
        .post(format!("{}/oauth/token", creds.sentin8_auth_url))
        .form(&RefreshTokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: creds.refresh_token.clone(),
            client_id,
        })
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("refresh failed: HTTP {}", resp.status());
    }
    let token: TokenResponse = resp.json().await?;
    creds.access_token = token.access_token;
    if let Some(rt) = token.refresh_token {
        creds.refresh_token = rt;
    }
    creds.expires_at = chrono::Utc::now() + chrono::Duration::seconds(token.expires_in as i64);
    save_credentials(creds)?;
    Ok(())
}

fn save_credentials(creds: &Credentials) -> anyhow::Result<()> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)?;
    fs::write(&path, json)?;
    // Set file permissions to 0600 (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Discover all available command scopes from the sys service's
/// `GET /v1/scopes/catalog` endpoint. Returns a space-separated string
/// of all distinct scopes. Falls back to an empty string if unreachable.
async fn discover_command_scopes() -> String {
    // Resolve the sys service URL from the config or environment.
    let sys_url = std::env::var("SENTIN8_SYS_URL")
        .unwrap_or_else(|_| "https://sys.ops.sys.local.sentin8.dev".to_string());

    // Query the scope catalog - this is a public endpoint that doesn't
    // require authentication (it returns the platform's well-known scopes).
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let connect = tokio::time::timeout(
        Duration::from_secs(3),
        client.get(format!("{sys_url}/v1/scopes/catalog")).send(),
    )
    .await;

    let resp = match connect {
        Ok(Ok(r)) => r,
        _ => return String::new(),
    };

    if !resp.status().is_success() {
        return String::new();
    }

    // The response is a JSON array of scope strings, or an object with
    // a "scopes" key containing the array.
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    let scopes: Vec<String> = if let Some(arr) = body.as_array() {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    } else if let Some(obj) = body.as_object() {
        if let Some(arr) = obj.get("scopes").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    if scopes.is_empty() {
        String::new()
    } else {
        scopes.join(" ")
    }
}

fn load_credentials() -> Option<Credentials> {
    let path = credentials_path();
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Decode basic user info from a JWT access token (no signature verification -
/// display only).
pub fn decode_user_info(token: &str) -> Option<UserInfo> {
    let claims: serde_json::Value = sentin8::auth::jwt::decode_payload(token).ok()?;
    Some(UserInfo {
        email: claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from),
        subject_id: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        scopes: claims
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default(),
        org_id: claims
            .get("org_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        env_id: claims
            .get("env_id")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// System env UUID (ops) - the default env for platform-scoped commands.
pub const SYSTEM_ENV_ID: &str = "00000000-0000-0000-0000-000000000002";

/// Check whether a target env_id is the system env (ops).
fn is_system_env(env_id: &str) -> bool {
    env_id == SYSTEM_ENV_ID
        || env_id == "ops"
        || env_id.to_lowercase() == "00000000-0000-0000-0000-000000000002"
}

/// Obtain a token for calling a target service in a specific env.
///
/// For platform-scoped commands (target env = system/ops), the CLI's own
/// device-flow user token is used directly - no delegation needed.
///
/// For tenant env-scoped commands, the CLI requests a delegated token via
/// the Delegation Gateway (`POST /delegate/access-token`). The CLI's user
/// token serves as the `act_sub`/`act_email` identity, and the CLI's M2M
/// client (`cli-delegator`) cert-bound token is used as the M2M token for
/// the delegation call. If the M2M client is not yet registered, falls back
/// to the user token directly (with a warning) - this preserves backward
/// compatibility during the transition period.
///
/// See `sentin8-sentin8-cli-technical-design.md` §3.2.
pub async fn get_token_for_env(
    target_env_id: &str,
    scope: &str,
    audience: &str,
) -> anyhow::Result<String> {
    // Platform-scoped: use the stored user token directly.
    if is_system_env(target_env_id) {
        return get_valid_token().await;
    }

    // Env-scoped: attempt delegation via the Delegation Gateway.
    let user_token = get_valid_token().await?;

    // Decode the user's identity from their token for the `act` claim.
    let user_info = decode_user_info(&user_token)
        .ok_or_else(|| anyhow::anyhow!("failed to decode user token for delegation"))?;

    // auth DESIGN §4.3f: the `cli-delegator` CERTIFICATE is
    // the identity - the mTLS transport presents it on the delegation
    // call; Auth's TLS layer authenticates the handshake and mints the
    // cert-bound delegated token. If the certificate cannot be ensured
    // (first run without the enrollment claim), fall back to the user
    // token (delegation degrades; works only platform-scoped).
    let auth_url = crate::config::sentin8_auth_url();

    let delegator_transport = get_cli_delegator_transport(&auth_url).await;
    if let Err(e) = &delegator_transport {
        tracing_debug(&format!(
            "cli-delegator transport unavailable ({e}), falling back to user token"
        ));
    }

    // Attempt delegation on the cert-presenting transport.
    let delegator_transport = match delegator_transport {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Warning: delegation transport unavailable ({e}), using user token directly. \
                 Run 'sentin8-cli signin' if the token is expired."
            );
            return Ok(user_token);
        }
    };
    match delegator_transport
        .post(format!(
            "{}/delegate/access-token",
            auth_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "act_sub": user_info.subject_id,
            "act_email": user_info.email,
            "env_id": target_env_id,
            "scope": scope,
            "audience": audience,
        }))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("delegation failed: {status} {body}");
            }
            #[derive(serde::Deserialize)]
            struct DelegatedResponse {
                access_token: String,
            }
            let delegated: DelegatedResponse = resp.json().await?;
            tracing_debug(&format!(
                "delegated token obtained for env {} (scope={}, aud={})",
                target_env_id, scope, audience
            ));
            Ok(delegated.access_token)
        }
        Err(e) => {
            // Fall back to the user token with a warning. This allows
            // commands to work when the delegation endpoint is not yet
            // available or the user has direct access to the target env.
            eprintln!(
                "Warning: delegation failed ({e}), using user token directly. \
                 Run 'sentin8-cli signin' if the token is expired."
            );
            Ok(user_token)
        }
    }
}

/// Minimal logging without a tracing dependency - prints to stderr if
/// `SENTIN8_CLI_DEBUG` is set.
fn tracing_debug(msg: &str) {
    if std::env::var("SENTIN8_CLI_DEBUG").is_ok() {
        eprintln!("[debug] {msg}");
    }
}

/// Build the cert-presenting transport for the `cli-delegator` workload
/// (auth DESIGN §4.3f) - the certificate IS the identity:
/// load-or-mint from Acme (`cli-delegator` is grant-declared), then the
/// mTLS transport presents it on every call; Auth's TLS layer
/// authenticates the handshake. No M2M token exists on this path.
///
/// Returns the transport, or an error if issuance fails.
async fn get_cli_delegator_transport(auth_url: &str) -> anyhow::Result<reqwest::Client> {
    let _ = dotenvy::dotenv();

    let ca_cert_path = std::env::var("SENTIN8_CLI_CA_CERT_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(sentin8::auth::m2m::platform_ca_path);
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(auth_url, "cli-delegator", &ca_cert_path)
            .await
            .map_err(|e| anyhow::anyhow!("cli-delegator certificate: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("cli-delegator transport: {e}"))
}

/// Cert-presenting transport for the CLI's EVENT-PRODUCER workload
/// (`cli-producer`) (auth DESIGN §4.3f): the certificate IS
/// the identity - load-or-mint from Acme (the `cli-producer` grant row
/// is seeded by the e2e fleet setup / operator tooling), then the mTLS
/// transport presents it; Bus's TLS layer authenticates the handshake
/// and the registry map authorizes `sentin8:bus:produce` + stamps the
/// `sentin8` vertical for the VDC-2 ownership gate.
///
/// Returns the transport, or an error if issuance fails.
pub async fn get_cli_producer_transport(auth_url: &str) -> anyhow::Result<reqwest::Client> {
    let _ = dotenvy::dotenv();
    ensure_bootstrap_enrollment_for_mint()?;

    let ca_cert_path = std::env::var("SENTIN8_CLI_CA_CERT_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(sentin8::auth::m2m::try_platform_ca_path)
        .unwrap_or_else(|| {
            format!(
                "{}/ca/root-ca.crt",
                std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| {
                    format!(
                        "{}/.sentin8/acme",
                        std::env::var("HOME").unwrap_or_else(|_| ".".into())
                    )
                })
            )
        });
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(auth_url, "cli-producer", &ca_cert_path)
            .await
            .map_err(|e| anyhow::anyhow!("cli-producer certificate: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("cli-producer transport: {e}"))
}

/// Export the captain-brokered bootstrap enrollment claim for a FIRST-BIRTH
/// M2M mint (bus DESIGN §4.3, CLI-producer path).
///
/// The CLI is not captain-spawned: it never receives
/// `SENTIN8_BOOTSTRAP_ENROLLMENT(+_TS)` in its environment, so a first-birth
/// cert mint at acme (`POST /v1/client-cert`, the only unauthenticated
/// admission channel) is rejected 401 - the SDK's mint chain forwards the
/// enrollment headers exactly when the env is set. The claim brokered by
/// captain is sealed at rest
/// (`{run_dir}/bootstrap-enrollment.json.enc`, AES-256-GCM under the
/// bootstrap/auth master key; captain DESIGN §7): unseal it with the SAME
/// derivation acme uses for verification and export it into THIS process's
/// environment, making the CLI's mint indistinguishable from a
/// captain-spawned workload's. A live claim beats a stale one - when the
/// env vars are already present but outside the TTL, re-export from the
/// record (it is re-stamped by the captain's monitor; the env copy can
/// trail it) so the mint uses only a claim acme will admit.
fn ensure_bootstrap_enrollment_for_mint() -> anyhow::Result<()> {
    use sentin8::config::bootstrap;

    // Launcher parity (captain DESIGN §7): captain propagates the PUBLIC
    // Acme Root-CA path into every child; the SDK's DCR/mTLS channels read
    // `SENTIN8_TLS_CA_PEM` from the environment fail-closed.
    // A standalone CLI has neither - derive the same default launcher path
    // ({acme_dir}/ca/root-ca.crt) and export it for THIS process so the
    // identity channels never abort on a missing env var.
    for var in ["SENTIN8_TLS_CA_PEM", "SENTIN8_TLS_CLIENT_CA_PEM"] {
        let unset = std::env::var(var)
            .map(|v| v.trim().is_empty())
            .unwrap_or(true);
        if unset {
            let derived = format!(
                "{}/ca/root-ca.crt",
                std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| {
                    format!(
                        "{}/.sentin8/acme",
                        std::env::var("HOME").unwrap_or_else(|_| ".".into())
                    )
                })
            );
            // SAFETY(dev-tooling): process-startup export of a PUBLIC cert
            // path - the same value captain sets for its children.
            std::env::set_var(var, &derived);
            tracing_debug(&format!("exported {var}={derived} (launcher parity)"));
        }
    }

    let fresh_env = std::env::var("SENTIN8_BOOTSTRAP_ENROLLMENT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .zip(
            std::env::var("SENTIN8_BOOTSTRAP_ENROLLMENT_TS")
                .ok()
                .and_then(|ts| ts.parse::<i64>().ok()),
        )
        .filter(|(secret, ts)| bootstrap::claim_is_valid(secret, *ts));
    if fresh_env.is_some() {
        tracing_debug("bootstrap enrollment claim: fresh env copy - using it");
        return Ok(());
    }

    // Not exported (or stale): unseal the captain-maintained record.
    let material = std::env::var("SENTIN8_BOOTSTRAP_MASTER_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("SENTIN8_AUTH_MASTER_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no master key for the bootstrap enrollment record - set \
                 SENTIN8_BOOTSTRAP_MASTER_KEY (or SENTIN8_AUTH_MASTER_KEY)"
            )
        })?;
    let key = sentin8::crypto::derive_key(material.as_bytes());
    let record_path = sentin8::config::bootstrap::enrollment_record_path();
    let envelope = fs::read_to_string(&record_path).map_err(|e| {
        anyhow::anyhow!(
            "bootstrap enrollment record unreadable at {}: {e} - \
             is the fleet running (captain seals it at boot)?",
            record_path.display()
        )
    })?;
    let plaintext = sentin8::crypto::open_str(&key, &envelope)
        .map_err(|e| anyhow::anyhow!("bootstrap enrollment unseal failed: {e}"))?;
    let plaintext = String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("bootstrap enrollment record: invalid utf8: {e}"))?;
    let record: serde_json::Value = serde_json::from_str(&plaintext)
        .map_err(|e| anyhow::anyhow!("bootstrap enrollment record parse: {e}"))?;
    let secret = record["secret"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bootstrap enrollment record: missing secret"))?;
    let ts = record["generated_at"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("bootstrap enrollment record: missing generated_at"))?;
    if !bootstrap::claim_is_valid(secret, ts) {
        anyhow::bail!(
            "bootstrap enrollment claim (record) is outside its TTL - restart \
             the fleet to re-stamp"
        )
    }
    // SAFETY(dev-tooling): one-shot process-startup export of a claim the
    // caller already holds on disk - same channel captain uses for
    // workloads. Values are non-secret-derived (hex claim + unix ts).
    std::env::set_var(bootstrap::ENV_ENROLLMENT, secret);
    std::env::set_var(bootstrap::ENV_ENROLLMENT_TS, ts.to_string());
    tracing_debug("bootstrap enrollment claim: loaded from the sealed record");
    Ok(())
}
