// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:CLI starter self-registration (`--print-registration`).
//!
//! The CLI binary is the described unit (RS §6 composable enrollment):
//! `vertical enroll ../sentin8-cli` probes it like any platform service and
//! upserts the declared M2M workload grant rows, so the CLI's own workloads
//! provision through the standard enroll pass - no SQL in test fixtures or
//! reset scripts (auth DESIGN §4.3f, bus DESIGN §4.3).

use sentin8::registration::{AdminScope, M2mGrant, Registration};

/// The CLI's M2M workloads:
/// - `cli-producer`: event producer for one-shot produces from operator
///   tooling (the bus gate is M2M-only - ownership is a workload property,
///   never a user-token claim);
/// - `cli-delegator`: delegated-call broker (the CLI presents its
///   certificate and Auth mints a `cnf`-bound delegated JWT for
///   `sentin8 call` dispatch);
/// - `sentin8-cli-tls`: the database-free HostContextResolver's resolve
///   workload (cache miss calls Sys `GET /v1/resolve/hostname`).
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "cli-producer",
        scopes: &["sentin8:bus:produce"],
    },
    M2mGrant {
        workload: "cli-delegator",
        scopes: &[],
    },
    M2mGrant {
        workload: "sentin8-cli-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Admin scopes the signed-in operator's delegated tokens carry. The CLI
/// dispatches through registry-declared commands (`sentin8_cli_commands`),
/// so the closed set is the platform vocabulary the registry commands
/// reference.
const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Tuple("sentin8:cli:admin", "sentin8:sys:memberships:admin"),
    AdminScope::Tuple("sentin8:cli:admin", "sentin8:auth:users:read"),
    AdminScope::Tuple("sentin8:cli:admin", "sentin8:auth:users:write"),
    AdminScope::Tuple("sentin8:cli:admin", "sentin8:bus:produce"),
];

/// The OpenAPI spec closure - the CLI is an operator-tooling binary with no
/// HTTP surface of its own, so the closure emits `null` (the enroll path
/// skips empty openapi output; the proxy's precedent).
fn openapi_spec() -> serde_json::Value {
    serde_json::Value::Null
}

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:cli",
        subdomain: "cli",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: None,
        sql_migrations: vec![],
        pg_roles: &[],
        policies: &[],
        relations: &[],
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}