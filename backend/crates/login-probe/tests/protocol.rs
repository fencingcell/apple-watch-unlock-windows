use std::time::{Duration, Instant};
use watch_login_probe::transport::{Peers, Transfer};
use watch_unlock_auth::{key_fingerprint, public_key_hex, sign_approval, Request, SigningKey};
fn frame(offset: usize, total: usize, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(offset as u16).to_be_bytes());
    v.extend_from_slice(&(total as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn request() -> Request {
    Request {
        protocol_version: 1,
        purpose: "probe".into(),
        computer_id: key_fingerprint(&hex::decode(public_key_hex(&key(1))).unwrap()).unwrap(),
        account_sid: "S-1-0-0".into(),
        session_id: 0,
        nonce: "ab".repeat(32),
        expires_at_ms: 31_000,
        computer_name: "Test PC".into(),
        account_name: "Authentication test".into(),
    }
}
#[test]
fn partial_payload_reassembles() {
    let mut t = Transfer::default();
    assert_eq!(t.push(&frame(0, 19, &[1; 16])).unwrap(), None);
    assert_eq!(
        t.push(&frame(16, 19, &[2; 3])).unwrap().unwrap(),
        [vec![1; 16], vec![2; 3]].concat()
    );
}
#[test]
fn malformed_frames_reject() {
    for f in [
        frame(0, 4097, &[0]),
        frame(1, 2, &[0]),
        frame(0, 1, &[0, 1]),
        frame(0, 0, &[]),
        frame(0, 17, &[0; 17]),
    ] {
        assert!(Transfer::default().push(&f).is_err());
    }
}
#[test]
fn duplicate_out_of_order_and_total_mismatch_reject() {
    for f in [frame(0, 20, &[1]), frame(17, 20, &[1]), frame(16, 21, &[1])] {
        let mut t = Transfer::default();
        t.push(&frame(0, 20, &[0; 16])).unwrap();
        assert!(t.push(&f).is_err());
        assert!(
            t.push(&frame(16, 20, &[0; 4])).is_err(),
            "invalid transfer must stay poisoned until control reset"
        );
    }
}
fn peers() -> Peers {
    Peers::new(Some(hex::decode(public_key_hex(&key(2))).unwrap()))
}
fn send(p: &mut Peers, peer: &str, signer: u8, now: Instant, wall: u64) -> anyhow::Result<bool> {
    let bytes = serde_json::to_vec(&sign_approval(&request(), &key(signer)).unwrap()).unwrap();
    let mut accepted = false;
    for (i, chunk) in bytes.chunks(16).enumerate() {
        accepted = p.write(peer, &frame(i * 16, bytes.len(), chunk), wall, now)?;
    }
    Ok(accepted)
}
fn begin(p: &mut Peers, now: Instant) {
    p.start("a", request(), vec![7; 19], 1000, now).unwrap();
    p.read("a", 1000, now).unwrap();
    p.read("a", 1000, now).unwrap();
}
#[test]
fn valid_enrolled_approval_succeeds_once() {
    let now = Instant::now();
    let mut p = peers();
    begin(&mut p, now);
    assert!(send(&mut p, "a", 2, now, 1000).unwrap());
    assert!(send(&mut p, "a", 2, now, 1000).is_err());
}
#[test]
fn failed_authorization_and_unpaired_reject() {
    let now = Instant::now();
    for mut p in [peers(), Peers::new(None)] {
        begin(&mut p, now);
        assert!(send(&mut p, "a", 3, now, 1000).is_err());
    }
}
#[test]
fn cross_peer_rejects_without_consuming_owner() {
    let now = Instant::now();
    let mut p = peers();
    begin(&mut p, now);
    assert!(send(&mut p, "b", 2, now, 1000).is_err());
    assert!(send(&mut p, "a", 2, now, 1000).unwrap());
}
#[test]
fn monotonic_expiry_and_wall_expiry_reject() {
    for (seconds, wall) in [(30, 1000), (0, 31_000), (0, 999)] {
        let now = Instant::now();
        let mut p = peers();
        begin(&mut p, now);
        assert!(send(&mut p, "a", 2, now + Duration::from_secs(seconds), wall).is_err());
    }
}
#[test]
fn approval_requires_completed_request_read() {
    let now = Instant::now();
    let mut p = peers();
    p.start("a", request(), vec![7; 19], 1000, now).unwrap();
    assert!(send(&mut p, "a", 2, now, 1000).is_err());
}
#[test]
fn peer_bound_and_probe_only() {
    let now = Instant::now();
    let mut p = peers();
    for i in 0..8 {
        p.start(&i.to_string(), request(), vec![1], 1000, now)
            .unwrap();
    }
    assert!(p.start("9", request(), vec![1], 1000, now).is_err());
    let mut r = request();
    r.purpose = "logon".into();
    assert!(p.start("0", r, vec![1], 1000, now).is_err());
}
#[test]
fn completed_frame_cannot_be_reused() {
    let mut t = Transfer::default();
    assert_eq!(t.push(&frame(0, 1, &[9])).unwrap(), Some(vec![9]));
    assert!(t.push(&frame(0, 1, &[9])).is_err());
}
#[test]
fn exact_4096_byte_transfer_is_bounded_and_supported() {
    let mut t = Transfer::default();
    for i in 0..256 {
        let result = t.push(&frame(i * 16, 4096, &[3; 16])).unwrap();
        if i < 255 {
            assert!(result.is_none());
        } else {
            assert_eq!(result.unwrap(), vec![3; 4096]);
        }
    }
}
#[test]
fn disconnect_and_shutdown_drop_pending_state() {
    let now = Instant::now();
    let mut p = peers();
    begin(&mut p, now);
    p.remove("a");
    assert!(send(&mut p, "a", 2, now, 1000).is_err());
    begin(&mut p, now);
    p.clear();
    assert!(send(&mut p, "a", 2, now, 1000).is_err());
}
#[test]
fn control_reset_drops_partial_approval() {
    let now = Instant::now();
    let mut p = peers();
    begin(&mut p, now);
    assert!(!p.write("a", &frame(0, 100, &[0; 16]), 1000, now).unwrap());
    begin(&mut p, now);
    assert!(send(&mut p, "a", 2, now, 1000).unwrap());
}
#[test]
fn corrupt_json_requires_control_reset() {
    let now = Instant::now();
    let mut p = peers();
    begin(&mut p, now);
    assert!(p.write("a", &frame(0, 1, b"{"), 1000, now).is_err());
    assert!(send(&mut p, "a", 2, now, 1000).is_err());
    begin(&mut p, now);
    assert!(send(&mut p, "a", 2, now, 1000).unwrap());
}
