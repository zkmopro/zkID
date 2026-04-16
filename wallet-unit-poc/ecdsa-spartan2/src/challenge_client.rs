//! Client for the go-zkid-verifier challenge server.
//!
//! Fetches cryptographic challenges from the verifier server.

use std::error::Error;

const DEFAULT_SERVER_URL: &str = "http://localhost:8080";
const MAX_RETRIES: usize = 3;

#[derive(Debug, serde::Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge_bytes: String,
    pub expires_at: String,
}

/// Fetch a fresh challenge from the verifier server via `POST /challenge`.
///
/// Retries up to 3 times on transient failures before returning an error.
pub fn create_challenge(server_url: &str) -> Result<ChallengeResponse, Box<dyn Error>> {
    let url = format!("{}/challenge", server_url.trim_end_matches('/'));

    let mut last_err = None;
    for attempt in 1..=MAX_RETRIES {
        match ureq::post(&url).send_bytes(&[]) {
            Ok(resp) => return Ok(resp.into_json()?),
            Err(e) => {
                eprintln!(
                    "Challenge server attempt {}/{} failed: {}",
                    attempt, MAX_RETRIES, e
                );
                last_err = Some(e);
                if attempt < MAX_RETRIES {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
    Err(format!(
        "challenge server at {} unreachable after {} attempts: {}",
        server_url,
        MAX_RETRIES,
        last_err.unwrap()
    )
    .into())
}

/// Returns the default challenge server URL.
pub fn default_server_url() -> &'static str {
    DEFAULT_SERVER_URL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response_deserialization() {
        let json = r#"{
            "challenge_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "challenge_bytes": "deadbeefcafebabe1234567890abcde",
            "expires_at": "2026-01-01T00:00:00Z"
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.challenge_id, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        assert_eq!(resp.challenge_bytes, "deadbeefcafebabe1234567890abcde");
        assert_eq!(resp.expires_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_challenge_response_deserialization_minimal() {
        let json = r#"{
            "challenge_id": "00000000000000000000000000000000",
            "challenge_bytes": "0000000000000000000000000000000",
            "expires_at": "any-string-works"
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_at, "any-string-works");
    }

    #[test]
    #[ignore] // requires live challenge server on localhost:8080
    fn test_fetch_challenge_live() {
        let resp = create_challenge(DEFAULT_SERVER_URL).unwrap();
        assert!(!resp.challenge_id.is_empty());
        assert!(!resp.challenge_bytes.is_empty());
    }
}
