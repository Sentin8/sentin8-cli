// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Captain transport - TCP (reqwest) or local Unix socket (design §6.1.2).
//!
//! When no remote captain URL is configured (`SENTIN8_SENTIN8_CAPTAIN_URL`
//! env / `captain_url` config key unset) and the local control socket
//! `{run_dir()}/captain.sock` exists, every `captain` command talks to
//! captain over the UDS instead of TCP. The socket authorizes by
//! kernel-proven peer credentials (`SO_PEERCRED` - root or the socket
//! owner), so signed-out `make start/stop/status` work locally without a
//! Bearer token (the `systemctl` model). A remote URL - or a missing
//! socket (Windows, captain not yet started) - falls back to the plain
//! reqwest TCP path, which keeps requiring the signed-in operator token.
//!
//! reqwest cannot be pointed at a UDS (its connector API is sealed), so
//! the UDS path uses a small hyper-util legacy client with a Unix-socket
//! connector. Requests target the dummy authority `http://captain.local`
//! (hyper ignores the host on a UDS connection) with the real path.

use std::task::{Context, Poll};

use tower::Service;

/// Which transport a captain command should use.
#[derive(Debug, Clone)]
pub enum CaptainTransport {
    /// Remote / plain HTTP - the default reqwest path (token-gated).
    Tcp,
    /// Local Unix control socket (kernel-proven peer credentials).
    Unix { socket_path: String },
}

impl CaptainTransport {
    /// Resolve the transport for a captain command.
    ///
    /// UDS is preferred only when no explicit remote URL is configured -
    /// a configured `captain_url`/env always wins (remote captain: root
    /// on machine A proves nothing to machine B).
    pub fn resolve() -> Self {
        let remote = crate::config::Sentin8Config::load()
            .captain_url
            .or_else(|| std::env::var("SENTIN8_SENTIN8_CAPTAIN_URL").ok());
        #[cfg(unix)]
        if remote.is_none() {
            let path = sentin8::config::captain_socket_file();
            if std::path::Path::new(&path).exists() {
                return CaptainTransport::Unix { socket_path: path };
            }
        }
        #[cfg(not(unix))]
        let _ = remote;
        CaptainTransport::Tcp
    }

    /// Is this the local UDS transport? (CLI uses this to skip the
    /// DEVUI-1.3 sign-in gate - peer credentials are the authorization.)
    pub fn is_local_socket(&self) -> bool {
        matches!(self, CaptainTransport::Unix { .. })
    }

    /// Could this CLI reach captain over the local control socket?
    ///
    /// Unlike [`Self::resolve`], this does NOT require the socket file to
    /// exist right now - it only checks that no remote URL is configured
    /// (and the platform supports UDS). Used by `start`/`restart`: the
    /// socket cannot pre-exist when captain is down - the spawned captain
    /// creates it, and the caller is by definition on this machine. The
    /// kernel-proven peer credentials of the API calls made AFTER the
    /// spawn are the authorization; requiring a token to spawn would
    /// defeat the whole §6.1.2 local-operator model.
    pub fn local_control_possible() -> bool {
        let remote = crate::config::Sentin8Config::load()
            .captain_url
            .or_else(|| std::env::var("SENTIN8_SENTIN8_CAPTAIN_URL").ok());
        #[cfg(unix)]
        return remote.is_none();
        #[cfg(not(unix))]
        return remote.is_none() && false;
    }
}

/// An HTTP/1.1 client bound to the local captain control socket.
#[derive(Clone)]
pub struct UdsClient {
    inner: hyper_util::client::legacy::Client<UdsConnector, http_body_util::Full<bytes::Bytes>>,
}

/// A hyper service connector that opens the captain control socket.
#[derive(Clone)]
struct UdsConnector {
    socket_path: std::sync::Arc<String>,
}

impl Service<hyper::Uri> for UdsConnector {
    // TokioIo bridges tokio's AsyncRead/AsyncWrite to hyper's rt traits and
    // carries hyper-util's `Connection` impl (tokio UnixStream already
    // implements it), satisfying the legacy client's connector bounds.
    type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: hyper::Uri) -> Self::Future {
        let path = self.socket_path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(path.as_str()).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

impl UdsClient {
    /// Build a client bound to `socket_path`.
    pub fn new(socket_path: String) -> Self {
        let connector = UdsConnector {
            socket_path: std::sync::Arc::new(socket_path),
        };
        Self {
            inner:
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .build(connector),
        }
    }

    /// Perform a request. `path` must start with `/`.
    ///
    /// Returns `(status, body_bytes)` - captain command handlers only
    /// ever read JSON or stream SSE; the SSE case uses [`Self::request_stream`].
    pub async fn request(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(hyper::StatusCode, bytes::Bytes), anyhow::Error> {
        let resp = self.send(method, path, body).await?;
        let status = resp.status();
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await?
            .to_bytes();
        Ok((status, bytes))
    }

    /// Perform a request, returning the raw response for SSE streaming
    /// (body is `hyper::body::Incoming` - map to a data stream at the
    /// consumption site).
    pub async fn request_stream(
        &self,
        method: hyper::Method,
        path: &str,
    ) -> Result<http::Response<hyper::body::Incoming>, anyhow::Error> {
        self.send(method, path, None).await
    }

    async fn send(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<http::Response<hyper::body::Incoming>, anyhow::Error> {
        let uri: hyper::Uri = format!("http://captain.local{path}")
            .parse()
            .map_err(|e| anyhow::anyhow!("bad captain path {path}: {e}"))?;
        let mut builder = hyper::Request::builder().method(method).uri(uri);
        if let Some(json) = &body {
            builder = builder.header("content-type", "application/json");
            let bytes = serde_json::to_vec(json)?;
            let req = builder.body(http_body_util::Full::new(bytes.into()))?;
            let resp = self.inner.request(req).await?;
            return Ok(resp);
        }
        let req = builder.body(http_body_util::Full::new(bytes::Bytes::new()))?;
        let resp = self.inner.request(req).await?;
        Ok(resp)
    }
}

/// Decode a UDS JSON body (error-reporting path included).
pub fn uds_json<T: serde::de::DeserializeOwned>(
    status: hyper::StatusCode,
    body: &bytes::Bytes,
) -> Result<T, anyhow::Error> {
    if !status.is_success() {
        anyhow::bail!(
            "captain API error: {} {}",
            status,
            String::from_utf8_lossy(body)
        );
    }
    Ok(serde_json::from_slice(body)?)
}
