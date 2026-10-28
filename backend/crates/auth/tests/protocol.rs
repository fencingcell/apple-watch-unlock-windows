use watch_unlock_auth::*;

const NOW: u64 = 1_700_000_000_000;
fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}
fn public(key: &SigningKey) -> Vec<u8> {
    hex::decode(public_key_hex(key)).unwrap()
}
fn request() -> Request {
    Request {
        protocol_version: 1,
        purpose: "probe".into(),
        computer_id: key_fingerprint(&public(&key(1))).unwrap(),
        account_sid: "S-1-0-0".into(),
        session_id: 7,
        nonce: "ab".repeat(32),
        expires_at_ms: NOW + 30_000,
        computer_name: "Test PC".into(),
        account_name: "Authentication test".into(),
    }
}
#[test]
fn accepted_cryptographic_round_trip() {
    let request = request();
    let signed = sign_request(request.clone(), &key(1)).unwrap();
    signed.verify(&public(&key(1)), NOW).unwrap();
    let approval = sign_approval(&request, &key(2)).unwrap();
    approval.verify(&request, &public(&key(2)), NOW).unwrap();
    assert_eq!(signed.computer_public_key.len(), 130);
    assert_eq!(signed.signature.len(), 128);
    assert_eq!(approval.signature.len(), 128);
}
#[test]
fn tampering_all_bound_fields_is_rejected() {
    let original = request();
    let signed = sign_request(original.clone(), &key(1)).unwrap();
    let approval = sign_approval(&original, &key(2)).unwrap();
    for field in 0..10 {
        let mut altered = original.clone();
        match field {
            0 => altered.account_sid = "S-1-5-21-100".into(),
            1 => altered.session_id += 1,
            2 => altered.nonce = "cd".repeat(32),
            3 => altered.purpose = "logon".into(),
            4 => altered.computer_name = "Other PC".into(),
            5 => altered.account_name = "Other account".into(),
            6 => altered.computer_id = "ab".repeat(32),
            7 => altered.expires_at_ms -= 1,
            8 => altered.protocol_version = 2,
            _ => altered.purpose = "unlock".into(),
        }
        assert!(
            approval.verify(&altered, &public(&key(2)), NOW).is_err(),
            "field {field}"
        );
        let mut altered_signed = signed.clone();
        altered_signed.request = altered;
        assert!(
            altered_signed.verify(&public(&key(1)), NOW).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn pinned_keys_and_identity_are_required() {
    let r = request();
    let mut s = sign_request(r.clone(), &key(1)).unwrap();
    assert!(s.verify(&public(&key(3)), NOW).is_err());
    s.computer_public_key = public_key_hex(&key(3));
    assert!(s.verify(&public(&key(1)), NOW).is_err());
    let mut a = sign_approval(&r, &key(2)).unwrap();
    assert!(a.verify(&r, &public(&key(3)), NOW).is_err());
    a.watch_public_key = public_key_hex(&key(3));
    assert!(a.verify(&r, &public(&key(2)), NOW).is_err());
    let mut r = request();
    r.computer_id = "00".repeat(32);
    assert!(sign_request(r, &key(1)).is_err());
}
#[test]
fn lifetime_boundaries_are_enforced() {
    let r = request();
    let s = sign_request(r.clone(), &key(1)).unwrap();
    let a = sign_approval(&r, &key(2)).unwrap();
    for now in [NOW - 1, r.expires_at_ms, r.expires_at_ms + 1] {
        assert!(s.verify(&public(&key(1)), now).is_err());
        assert!(a.verify(&r, &public(&key(2)), now).is_err());
    }
    s.verify(&public(&key(1)), r.expires_at_ms - 1).unwrap();
}
#[test]
fn malformed_fields_reject_before_signing() {
    for field in 0..14 {
        let mut r = request();
        match field {
            0 => r.nonce = "AB".repeat(32),
            1 => r.nonce = "zz".repeat(32),
            2 => r.nonce.pop().map(|_| ()).unwrap(),
            3 => r.computer_id = "AB".repeat(32),
            4 => r.account_sid = "S-2-5-1".into(),
            5 => r.account_sid = "S-1-foo-1".into(),
            6 => r.account_sid = "S-1-5".into(),
            7 => r.account_sid = "S-1-5-4294967296".into(),
            8 => r.computer_name.clear(),
            9 => r.account_name = "bad\nname".into(),
            10 => r.computer_name = "é".repeat(41),
            11 => r.account_sid = "S-1-5-".to_string() + &"1-".repeat(100),
            12 => r.account_name = "a".repeat(81),
            _ => r.account_sid = "S-1-281474976710656-0".into(),
        }
        assert!(r.canonical_bytes().is_err(), "field {field}");
        assert!(sign_request(r, &key(1)).is_err(), "field {field}");
    }
}
#[test]
fn malformed_signature_key_hash_and_nonce_reject() {
    let r = request();
    let a = sign_approval(&r, &key(2)).unwrap();
    for field in 0..6 {
        let mut changed = a.clone();
        match field {
            0 => changed.signature = "ff".repeat(64),
            1 => changed.signature = "AA".repeat(64),
            2 => changed.watch_public_key = "00".repeat(65),
            3 => changed.request_hash = "00".repeat(32),
            4 => changed.nonce = "00".repeat(32),
            _ => changed.signature.truncate(126),
        }
        assert!(changed.verify(&r, &public(&key(2)), NOW).is_err());
    }
    assert!(key_fingerprint(&[0; 65]).is_err());
}
#[test]
fn failed_attempt_does_not_consume_and_success_cannot_replay() {
    let r = request();
    let a = sign_approval(&r, &key(2)).unwrap();
    let mut pending = PendingApproval::new(r.clone(), NOW).unwrap();
    let mut invalid = a.clone();
    invalid.signature = "00".repeat(64);
    assert!(pending.accept(&invalid, &public(&key(2)), NOW).is_err());
    assert!(pending.accept(&a, &public(&key(3)), NOW).is_err());
    pending.accept(&a, &public(&key(2)), NOW).unwrap();
    assert_eq!(
        pending.accept(&a, &public(&key(2)), NOW),
        Err(AuthError::Consumed)
    );
}
#[test]
fn pending_rejects_clock_rollback_and_foreign_request() {
    let r = request();
    let mut foreign = r.clone();
    foreign.session_id += 1;
    let foreign = sign_approval(&foreign, &key(2)).unwrap();
    let valid = sign_approval(&r, &key(2)).unwrap();
    let mut pending = PendingApproval::new(r.clone(), NOW + 100).unwrap();
    assert!(pending.accept(&valid, &public(&key(2)), NOW + 99).is_err());
    assert!(pending
        .accept(&foreign, &public(&key(2)), NOW + 100)
        .is_err());
    pending.accept(&valid, &public(&key(2)), NOW + 100).unwrap();
    assert!(PendingApproval::new(r.clone(), NOW - 1).is_err());
    assert!(PendingApproval::new(r.clone(), r.expires_at_ms).is_err());
}
#[test]
fn canonical_contract_has_exact_order_and_big_endian_lengths() {
    let mut r = request();
    r.computer_name = "电脑".into();
    let mut expected = b"WATCH-LOGIN-REQUEST-V1\0".to_vec();
    expected.extend_from_slice(&[1, 0]);
    expected.extend_from_slice(&hex::decode(&r.computer_id).unwrap());
    expected.extend_from_slice(&[0, 7]);
    expected.extend_from_slice(b"S-1-0-0");
    expected.extend_from_slice(&7u32.to_be_bytes());
    expected.extend_from_slice(&[0xab; 32]);
    expected.extend_from_slice(&r.expires_at_ms.to_be_bytes());
    expected.extend_from_slice(&[0, 6]);
    expected.extend_from_slice("电脑".as_bytes());
    expected.extend_from_slice(&[0, 19]);
    expected.extend_from_slice(b"Authentication test");
    assert_eq!(r.canonical_bytes().unwrap(), expected);
}
#[test]
fn strict_json_rejects_unknown_duplicate_and_wrong_type_fields() {
    let value = serde_json::to_value(request()).unwrap();
    let mut unknown = value.clone();
    unknown["extra"] = true.into();
    assert!(serde_json::from_value::<Request>(unknown).is_err());
    let duplicate =
        serde_json::to_string(&value)
            .unwrap()
            .replacen("{", "{\"protocol_version\":1,", 1);
    assert!(serde_json::from_str::<Request>(&duplicate).is_err());
    let mut value = value;
    value["session_id"] = "7".into();
    assert!(serde_json::from_value::<Request>(value).is_err());
}

#[test]
fn fixed_synthetic_interoperability_vectors() {
    use sha2::{Digest, Sha256};
    let r = request();
    let signed = sign_request(r.clone(), &key(1)).unwrap();
    let approval = sign_approval(&r, &key(2)).unwrap();
    let canonical = r.canonical_bytes().unwrap();
    let mut approval_bytes = b"WATCH-LOGIN-APPROVAL-V1\0".to_vec();
    approval_bytes.extend_from_slice(&Sha256::digest(&canonical));
    let expected = serde_json::json!({
        "protocol_version": 1,
        "warning": "SYNTHETIC TEST KEYS ONLY. Public private scalars below are not secrets; never use these keys for enrollment.",
        "algorithm": "ECDSA P-256 with SHA-256; X9.63 uncompressed 65-byte public keys; IEEE P1363 64-byte signatures; lowercase hex",
        "now_ms": NOW,
        "computer_private_scalar_hex_SYNTHETIC": "01".repeat(32),
        "watch_private_scalar_hex_SYNTHETIC": "02".repeat(32),
        "computer_public_key": public_key_hex(&key(1)),
        "watch_public_key": public_key_hex(&key(2)),
        "computer_fingerprint": key_fingerprint(&public(&key(1))).unwrap(),
        "watch_fingerprint": key_fingerprint(&public(&key(2))).unwrap(),
        "canonical_request_hex": hex::encode(&canonical),
        "request_hash": hex::encode(Sha256::digest(&canonical)),
        "approval_signing_bytes_hex": hex::encode(&approval_bytes),
        "signed_request": signed,
        "signed_approval": approval
    });
    let actual: serde_json::Value =
        serde_json::from_str(include_str!("../../../../protocol/v1.json")).unwrap();
    assert_eq!(actual, expected);
    let signed: SignedRequest = serde_json::from_value(actual["signed_request"].clone()).unwrap();
    let approval: SignedApproval =
        serde_json::from_value(actual["signed_approval"].clone()).unwrap();
    signed.verify(&public(&key(1)), NOW).unwrap();
    approval
        .verify(&signed.request, &public(&key(2)), NOW)
        .unwrap();
}
