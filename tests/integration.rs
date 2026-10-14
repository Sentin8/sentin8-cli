// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
// SPDX-License-Identifier: Apache-2.0

// Sentin8 CLI unit tests — Story 9.1.8

#[test]
fn credentials_path_not_empty() {
    let path = sentin8_cli::config::credentials_path();
    assert!(path.to_string_lossy().contains(".sentin8"));
    assert!(path.to_string_lossy().contains("credentials"));
}

#[test]
fn auth_url_config_not_empty() {
    let url = sentin8_cli::config::sentin8_auth_url();
    assert!(!url.is_empty());
}

#[test]
fn func_url_config_not_empty() {
    let url = sentin8_cli::config::sentin8_func_url();
    assert!(!url.is_empty());
}

#[test]
fn decode_user_info_rejects_invalid_token() {
    let info = sentin8_cli::auth::decode_user_info("not-a-jwt");
    assert!(info.is_none());
}

#[test]
fn decode_user_info_rejects_empty_input() {
    let info = sentin8_cli::auth::decode_user_info("");
    assert!(info.is_none());
}

#[test]
fn decode_user_info_parses_valid_jwt() {
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        b"{\"sub\":\"user-123\",\"email\":\"user@example.com\",\"scope\":\"openid profile\"}",
    );
    let token = format!("{header}.{payload}.sig");

    let info = sentin8_cli::auth::decode_user_info(&token);
    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.subject_id, "user-123");
}
