// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

//! Config file management — `~/.sentin8/config` (JSON, 0644).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sentin8Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentin8_auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentin8_func_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captain_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_env_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Sentin8Config {
    pub fn load() -> Self {
        let path = config_path();
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "platform_url" => self.platform_url.clone(),
            "sentin8_auth_url" => self.sentin8_auth_url.clone(),
            "sentin8_func_url" => self.sentin8_func_url.clone(),
            "captain_url" => self.captain_url.clone(),
            "client_id" => self.client_id.clone(),
            "default_org_id" => self.default_org_id.clone(),
            "default_env_id" => self.default_env_id.clone(),
            _ => self.extra.get(key).map(|v| v.to_string()),
        }
    }
}

pub fn config_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sentin8").join("config")
}

pub fn credentials_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sentin8").join("credentials")
}

pub fn set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = Sentin8Config::load();
    match key {
        "platform_url" => config.platform_url = Some(value.into()),
        "sentin8_auth_url" => config.sentin8_auth_url = Some(value.into()),
        "sentin8_func_url" => config.sentin8_func_url = Some(value.into()),
        "captain_url" => config.captain_url = Some(value.into()),
        "client_id" => config.client_id = Some(value.into()),
        "default_org_id" => config.default_org_id = Some(value.into()),
        "default_env_id" => config.default_env_id = Some(value.into()),
        _ => {
            config.extra.insert(key.into(), serde_json::json!(value));
        }
    }
    config.save()?;
    println!("Set {key} = {value}");
    Ok(())
}

pub fn get(key: &str) -> anyhow::Result<()> {
    let config = Sentin8Config::load();
    match config.get(key) {
        Some(value) => println!("{key} = {value}"),
        None => println!("{key} is not set"),
    }
    Ok(())
}

/// Get the configured func URL (config file or env var or default).
pub fn sentin8_func_url() -> String {
    let config = Sentin8Config::load();
    config
        .sentin8_func_url
        .or_else(|| std::env::var("SENTIN8_SENTIN8_FUNC_URL").ok())
        .unwrap_or_else(|| "https://sentin8-func.ops.sys.sentin8.local".into())
}

/// Get the configured captain URL (config file or env var or default).
pub fn captain_url() -> String {
    let config = Sentin8Config::load();
    config
        .captain_url
        .or_else(|| std::env::var("SENTIN8_SENTIN8_CAPTAIN_URL").ok())
        .unwrap_or_else(|| format!("http://localhost:{}", sentin8::config::captain_port()))
}

/// Get the configured auth URL (config file or env var or default).
pub fn sentin8_auth_url() -> String {
    let config = Sentin8Config::load();
    config
        .sentin8_auth_url
        .or_else(|| std::env::var("SENTIN8_SENTIN8_AUTH_URL").ok())
        .unwrap_or_else(|| "https://auth.ops.sys.sentin8.local".into())
}
