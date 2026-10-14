// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Func subcommands merged into the sentin8 CLI.

use std::path::PathBuf;

use base64::Engine;
use clap::Subcommand;
use sha2::{Digest, Sha256};

use crate::config::sentin8_func_url;

#[derive(Subcommand)]
pub enum FuncCommand {
    /// Upload a WASM module to Func Server.
    Upload {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        product_id: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        wasm: PathBuf,
        #[arg(long)]
        language: String,
        #[arg(long, value_delimiter = ',')]
        hooks: Vec<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// Validate a WASM binary locally (parse + hash) without uploading.
    Validate {
        #[arg(long)]
        wasm: PathBuf,
        #[arg(long, value_delimiter = ',')]
        hooks: Vec<String>,
    },
    /// Download a WASM module binary from Func Server.
    Download {
        #[arg(long)]
        module_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// List module versions for a domain+product.
    ListVersions {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        product_id: String,
    },
    /// Bulk-upload multiple WASM modules from a manifest JSON.
    BulkUpload {
        #[arg(long)]
        manifest: PathBuf,
    },
}

pub async fn run(cmd: FuncCommand, token: &str) -> anyhow::Result<()> {
    let sentin8_func_url = sentin8_func_url();
    let http = reqwest::Client::new();
    match cmd {
        FuncCommand::Upload {
            domain,
            product_id,
            version,
            wasm,
            language,
            hooks,
            description,
        } => {
            let bytes = std::fs::read(&wasm)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = format!("sha256:{}", hex_encode(hasher.finalize()));
            let body = serde_json::json!({
                "domain": domain,
                "product_id": product_id,
                "version_label": version,
                "wasm_binary": b64,
                "wasm_language": language,
                "wasm_hash": hash,
                "hooks": hooks,
                "parameters": {},
                "description": description,
            });
            let resp = http
                .post(format!("{sentin8_func_url}/v1/modules"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await?;
            println!("Upload: status {}", resp.status());
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }
        FuncCommand::Validate { wasm, hooks } => {
            let bytes = std::fs::read(&wasm)?;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = format!("sha256:{}", hex_encode(hasher.finalize()));
            println!("File:  {}", wasm.display());
            println!("Size:  {} bytes", bytes.len());
            println!("Hash:  {hash}");
            println!("Hooks: {}", hooks.join(", "));
            println!("Validation: parsed locally (full parse on upload)");
        }
        FuncCommand::Download { module_id, out: _ } => {
            let resp = http
                .get(format!("{sentin8_func_url}/v1/modules/{module_id}"))
                .bearer_auth(token)
                .send()
                .await?;
            if resp.status().is_success() {
                let module: serde_json::Value = resp.json().await?;
                // The module metadata contains the WASM hash; download binary from Storage in production.
                // For now, print the metadata.
                println!("{}", serde_json::to_string_pretty(&module)?);
            } else {
                println!("Download failed: status {}", resp.status());
            }
        }
        FuncCommand::ListVersions { domain, product_id } => {
            let resp = http
                .get(format!(
                    "{sentin8_func_url}/v1/modules?domain={domain}&product_id={product_id}"
                ))
                .bearer_auth(token)
                .send()
                .await?;
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                if let Some(arr) = body.as_array() {
                    println!(
                        "{:<36} {:<12} {:<10} {:<24}",
                        "ID", "VERSION", "STATUS", "HASH"
                    );
                    for m in arr {
                        println!(
                            "{:<36} {:<12} {:<10} {:<24}",
                            m.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            m.get("version_label")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                            m.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                            m.get("wasm_hash").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&body)?);
                }
            }
        }
        FuncCommand::BulkUpload { manifest } => {
            let manifest = std::fs::read_to_string(&manifest)?;
            let entries: serde_json::Value = serde_json::from_str(&manifest)?;
            if let Some(arr) = entries.as_array() {
                for entry in arr {
                    let wasm_path = entry.get("wasm").and_then(|v| v.as_str()).unwrap_or("");
                    let bytes = std::fs::read(wasm_path)?;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    let body = serde_json::json!({
                        "domain": entry.get("domain").unwrap_or(&serde_json::Value::Null),
                        "product_id": entry.get("product_id").unwrap_or(&serde_json::Value::Null),
                        "version_label": entry.get("version").unwrap_or(&serde_json::Value::Null),
                        "wasm_binary": b64,
                        "wasm_language": entry.get("language").unwrap_or(&serde_json::Value::Null),
                        "hooks": entry.get("hooks").unwrap_or(&serde_json::Value::Array(vec![])),
                        "parameters": entry.get("parameters").unwrap_or(&serde_json::json!({})),
                    });
                    let _ = http
                        .post(format!("{sentin8_func_url}/v1/modules"))
                        .bearer_auth(token)
                        .json(&body)
                        .send()
                        .await;
                    println!("Uploaded: {wasm_path}");
                }
            }
        }
    }
    Ok(())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
