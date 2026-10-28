//! Watch Login v1 authenticated challenge protocol. AGPL-3.0-only.
//! Cryptography: RustCrypto p256 and sha2 (MIT OR Apache-2.0).
pub use p256::ecdsa::SigningKey;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_CHALLENGE_LIFETIME_MS: u64 = 30_000;
const REQUEST_DOMAIN: &[u8] = b"WATCH-LOGIN-REQUEST-V1\0";
const APPROVAL_DOMAIN: &[u8] = b"WATCH-LOGIN-APPROVAL-V1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u8,
    pub purpose: String,
    pub computer_id: String,
    pub account_sid: String,
    pub session_id: u32,
    pub nonce: String,
    pub expires_at_ms: u64,
    pub computer_name: String,
    pub account_name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub request: Request,
    pub computer_public_key: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApproval {
    pub nonce: String,
    pub request_hash: String,
    pub watch_public_key: String,
    pub signature: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidRequest,
    InvalidEncoding,
    InvalidKey,
    InvalidSignature,
    Expired,
    InvalidLifetime,
    Mismatch,
    Consumed,
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid request fields",
            Self::InvalidEncoding => "expected exact-length lowercase hex",
            Self::InvalidKey => "expected a valid uncompressed P-256 public key",
            Self::InvalidSignature => "invalid P1363 P-256 signature",
            Self::Expired => "challenge has expired",
            Self::InvalidLifetime => {
                "challenge lifetime exceeds 30 seconds or clock moved backwards"
            }
            Self::Mismatch => "challenge or enrolled identity does not match",
            Self::Consumed => "challenge already consumed",
        })
    }
}
impl std::error::Error for AuthError {}

fn decode<const N: usize>(s: &str) -> Result<[u8; N], AuthError> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthError::InvalidEncoding);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(s, &mut bytes).map_err(|_| AuthError::InvalidEncoding)?;
    Ok(bytes)
}
fn validate_text(s: &str, max: usize) -> Result<(), AuthError> {
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(AuthError::InvalidRequest);
    }
    Ok(())
}
fn validate_sid(sid: &str) -> Result<(), AuthError> {
    validate_text(sid, 184)?;
    let parts: Vec<_> = sid.split('-').collect();
    // Windows SID: revision 1, 48-bit authority and 1..15 32-bit subauthorities.
    if !(4..=18).contains(&parts.len()) || parts[0] != "S" || parts[1] != "1" {
        return Err(AuthError::InvalidRequest);
    }
    for (index, part) in parts.iter().enumerate().skip(2) {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AuthError::InvalidRequest);
        }
        let n = part.parse::<u64>().map_err(|_| AuthError::InvalidRequest)?;
        if n > if index == 2 {
            (1u64 << 48) - 1
        } else {
            u32::MAX as u64
        } {
            return Err(AuthError::InvalidRequest);
        }
    }
    Ok(())
}
fn append_text(bytes: &mut Vec<u8>, s: &str) {
    bytes.extend_from_slice(&(s.len() as u16).to_be_bytes());
    bytes.extend_from_slice(s.as_bytes());
}
fn validate_time(request: &Request, now_ms: u64) -> Result<(), AuthError> {
    let remaining = request
        .expires_at_ms
        .checked_sub(now_ms)
        .ok_or(AuthError::Expired)?;
    if remaining == 0 {
        return Err(AuthError::Expired);
    }
    if remaining > MAX_CHALLENGE_LIFETIME_MS {
        return Err(AuthError::InvalidLifetime);
    }
    Ok(())
}
fn verifying_key(key: &[u8]) -> Result<VerifyingKey, AuthError> {
    if key.len() != 65 || key[0] != 4 {
        return Err(AuthError::InvalidKey);
    }
    VerifyingKey::from_sec1_bytes(key).map_err(|_| AuthError::InvalidKey)
}
fn verify_signature(key: &[u8], signature: &str, message: &[u8]) -> Result<(), AuthError> {
    let key = verifying_key(key)?;
    let signature = Signature::from_slice(&decode::<64>(signature)?)
        .map_err(|_| AuthError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| AuthError::InvalidSignature)
}
fn approval_bytes(request: &Request) -> Result<Vec<u8>, AuthError> {
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    bytes.extend_from_slice(&Sha256::digest(request.canonical_bytes()?));
    Ok(bytes)
}
impl Request {
    /// Canonical binary encoding, independent of JSON ordering or whitespace.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthError> {
        if self.protocol_version != 1 {
            return Err(AuthError::InvalidRequest);
        }
        let purpose = match self.purpose.as_str() {
            "probe" => 0,
            "logon" => 1,
            _ => return Err(AuthError::InvalidRequest),
        };
        let computer_id = decode::<32>(&self.computer_id)?;
        let nonce = decode::<32>(&self.nonce)?;
        validate_sid(&self.account_sid)?;
        validate_text(&self.computer_name, 80)?;
        validate_text(&self.account_name, 80)?;
        let mut bytes = REQUEST_DOMAIN.to_vec();
        bytes.extend_from_slice(&[self.protocol_version, purpose]);
        bytes.extend_from_slice(&computer_id);
        append_text(&mut bytes, &self.account_sid);
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        append_text(&mut bytes, &self.computer_name);
        append_text(&mut bytes, &self.account_name);
        Ok(bytes)
    }
}
impl SignedRequest {
    /// `expected_computer_key` must come from fingerprint-confirmed enrollment.
    pub fn verify(&self, expected_computer_key: &[u8], now_ms: u64) -> Result<(), AuthError> {
        let bytes = self.request.canonical_bytes()?;
        validate_time(&self.request, now_ms)?;
        let wire_key = decode::<65>(&self.computer_public_key)?;
        if wire_key != expected_computer_key
            || self.request.computer_id != key_fingerprint(expected_computer_key)?
        {
            return Err(AuthError::Mismatch);
        }
        verify_signature(expected_computer_key, &self.signature, &bytes)
    }
}
impl SignedApproval {
    /// Verification alone is stateless; use PendingApproval to prevent replay.
    pub fn verify(
        &self,
        request: &Request,
        expected_watch_key: &[u8],
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let bytes = approval_bytes(request)?;
        validate_time(request, now_ms)?;
        let nonce = decode::<32>(&self.nonce)?;
        let hash = decode::<32>(&self.request_hash)?;
        let wire_key = decode::<65>(&self.watch_public_key)?;
        if nonce != decode::<32>(&request.nonce)?
            || hash != bytes[APPROVAL_DOMAIN.len()..]
            || wire_key != expected_watch_key
        {
            return Err(AuthError::Mismatch);
        }
        verify_signature(expected_watch_key, &self.signature, &bytes)
    }
}
pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(false).as_bytes())
}
pub fn key_fingerprint(key: &[u8]) -> Result<String, AuthError> {
    verifying_key(key)?;
    Ok(hex::encode(Sha256::digest(key)))
}
/// The caller generates a fresh random 32-byte nonce and sets expiry <= now+30s.
pub fn sign_request(request: Request, key: &SigningKey) -> Result<SignedRequest, AuthError> {
    let bytes = request.canonical_bytes()?;
    let computer_public_key = public_key_hex(key);
    if request.computer_id != key_fingerprint(&decode::<65>(&computer_public_key)?)? {
        return Err(AuthError::Mismatch);
    }
    let signature: Signature = key.sign(&bytes);
    Ok(SignedRequest {
        request,
        computer_public_key,
        signature: hex::encode(signature.to_bytes()),
    })
}
pub fn sign_approval(request: &Request, key: &SigningKey) -> Result<SignedApproval, AuthError> {
    let bytes = approval_bytes(request)?;
    let signature: Signature = key.sign(&bytes);
    Ok(SignedApproval {
        nonce: request.nonce.clone(),
        request_hash: hex::encode(&bytes[APPROVAL_DOMAIN.len()..]),
        watch_public_key: public_key_hex(key),
        signature: hex::encode(signature.to_bytes()),
    })
}
/// Immutable request plus one-time state. Share behind a mutex across callers.
/// This type is intentionally not Clone: duplication would duplicate replay state.
pub struct PendingApproval {
    request: Request,
    created_at_ms: u64,
    consumed: bool,
}
impl PendingApproval {
    pub fn new(request: Request, now_ms: u64) -> Result<Self, AuthError> {
        request.canonical_bytes()?;
        validate_time(&request, now_ms)?;
        Ok(Self {
            request,
            created_at_ms: now_ms,
            consumed: false,
        })
    }
    pub fn accept(
        &mut self,
        approval: &SignedApproval,
        expected_watch_key: &[u8],
        now_ms: u64,
    ) -> Result<(), AuthError> {
        if self.consumed {
            return Err(AuthError::Consumed);
        }
        if now_ms < self.created_at_ms {
            return Err(AuthError::InvalidLifetime);
        }
        approval.verify(&self.request, expected_watch_key, now_ms)?;
        self.consumed = true;
        Ok(())
    }
}
