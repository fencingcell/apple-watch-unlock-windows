// SPDX-License-Identifier: AGPL-3.0-only
import XCTest
import CryptoKit
@testable import WatchLoginCore

final class ProtocolTests: XCTestCase {
    struct Vector: Decodable {
        var signed_request: SignedRequest
        var canonical_request_hex: String
        var request_hash: String
        var approval_signing_bytes_hex: String
        var watch_private_scalar_hex_SYNTHETIC: String
        var computer_private_scalar_hex_SYNTHETIC: String
        var watch_public_key: String
        var signed_approval: SignedApproval
        var now_ms: UInt64
    }
    func vector() throws -> Vector {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vector.self, from: Data(contentsOf: root.appendingPathComponent("protocol/v1.json")))
    }
    func testCanonicalAndCrossLanguageSignatures() throws {
        let v = try vector()
        let bytes = try v.signed_request.request.canonical()
        XCTAssertEqual(hex(bytes), v.canonical_request_hex)
        XCTAssertEqual(hex(Data(SHA256.hash(data: bytes))), v.request_hash)
        try v.signed_request.validate(now: v.now_ms)
        let key = try P256.Signing.PrivateKey(rawRepresentation: decodeHex(v.watch_private_scalar_hex_SYNTHETIC, count: 32))
        let approval = try SignedApproval.make(request: v.signed_request.request, key: key)
        XCTAssertEqual(approval.request_hash, v.request_hash)
        XCTAssertEqual(approval.watch_public_key, v.watch_public_key)
        let publicKey = try P256.Signing.PublicKey(x963Representation: decodeHex(v.watch_public_key, count: 65))
        let signing = try decodeHex(v.approval_signing_bytes_hex, count: 56)
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: decodeHex(approval.signature, count: 64)), for: signing))
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: decodeHex(v.signed_approval.signature, count: 64)), for: signing))
    }
    func testAlteredIdentitySessionNamesAndPurposeReject() throws {
        let v = try vector()
        for field in 0..<8 {
            var changed = v.signed_request
            switch field {
            case 0: changed.request.account_sid = "S-1-5-21"
            case 1: changed.request.session_id += 1
            case 2: changed.request.computer_name = "Other PC"
            case 3: changed.request.account_name = "Other user"
            case 4: changed.request.purpose = "logon"
            case 5: changed.request.computer_id = String(repeating: "00", count: 32)
            case 6: changed.signature = String(repeating: "00", count: 64)
            default: changed.computer_public_key = v.watch_public_key
            }
            XCTAssertThrowsError(try changed.validate(now: v.now_ms), "field \(field)")
        }
    }
    func testValidationBoundsAndEncoding() throws {
        let v = try vector()
        XCTAssertThrowsError(try v.signed_request.validate(now: v.now_ms - 1))
        XCTAssertThrowsError(try v.signed_request.validate(now: v.signed_request.request.expires_at_ms))
        for sid in ["S-2-1-0", "S-1-x-0", "", "S-1-1", "S-1-5-4294967296"] {
            var r = v.signed_request.request; r.account_sid = sid
            XCTAssertThrowsError(try r.canonical())
        }
        for name in ["", "bad\nname", String(repeating: "é", count: 41)] {
            var r = v.signed_request.request; r.computer_name = name
            XCTAssertThrowsError(try r.canonical())
        }
        XCTAssertThrowsError(try decodeHex("AB", count: 1))
        XCTAssertThrowsError(try decodeHex("0", count: 1))
        XCTAssertEqual(try decodeHex("ab", count: 1), Data([0xab]))
    }
    func testEnrollmentRequiresFullExplicitFingerprintAndChangedKey() throws {
        let v = try vector(); let key = v.signed_request.computer_public_key
        var enrollment = Enrollment()
        XCTAssertThrowsError(try enrollment.require(key))
        XCTAssertThrowsError(try enrollment.confirm(key, fingerprint: "short"))
        try enrollment.confirm(key, fingerprint: fingerprint(key))
        try enrollment.require(key)
        XCTAssertThrowsError(try enrollment.require(v.watch_public_key))
        XCTAssertEqual(enrollment.key, key)
    }
    func testFramesRoundTripAndRejectMalformedTransfers() throws {
        let payload = Data((0..<100).map(UInt8.init)); let peer = UUID()
        let frames = try Frames.encode(payload)
        XCTAssertTrue(frames.allSatisfy { $0.count <= 20 })
        var reader = Frames(); reader.start(peer: peer, now: 100)
        var result: Data?
        for frame in frames { result = try reader.append(frame, peer: peer, now: 101) }
        XCTAssertEqual(result, payload)
        XCTAssertThrowsError(try reader.append(frames[0], peer: peer, now: 102))
        for frame in [Data(), Data([0,0,0,0,1]), Data([0,1,0,2,1]), Data(repeating: 0, count: 21), Data([0,0,16,1,1])] {
            var bad = Frames(); bad.start(peer: peer, now: 1)
            XCTAssertThrowsError(try bad.append(frame, peer: peer, now: 2))
        }
        var other = Frames(); other.start(peer: peer, now: 1)
        XCTAssertThrowsError(try other.append(frames[0], peer: UUID(), now: 2))
        var stale = Frames(); stale.start(peer: peer, now: 1)
        XCTAssertThrowsError(try stale.append(frames[0], peer: peer, now: 30001))
        var inconsistent = Frames(); inconsistent.start(peer: peer, now: 1)
        _ = try inconsistent.append(frames[0], peer: peer, now: 2)
        var changed = frames[1]; changed[3] = 101
        XCTAssertThrowsError(try inconsistent.append(changed, peer: peer, now: 2))
        XCTAssertThrowsError(try Frames.encode(Data(repeating: 1, count: 4097)))
    }
    func testApprovalTokenCannotSurviveCancellationReplacementExpiryOrPeerChange() throws {
        let v = try vector(); let peer = UUID(); let key = v.signed_request.computer_public_key
        var gate = ApprovalGate()
        let token = try gate.begin(v.signed_request, peer: peer, now: v.now_ms, enrolled: key)
        gate.cancel()
        XCTAssertThrowsError(try gate.consume(token, peer: peer, now: v.now_ms))
        let old = try gate.begin(v.signed_request, peer: peer, now: v.now_ms, enrolled: key)
        let current = try gate.begin(v.signed_request, peer: peer, now: v.now_ms, enrolled: key)
        XCTAssertThrowsError(try gate.consume(old, peer: peer, now: v.now_ms))
        XCTAssertEqual(try gate.consume(current, peer: peer, now: v.now_ms), v.signed_request.request)
        XCTAssertThrowsError(try gate.consume(current, peer: peer, now: v.now_ms))
        let expired = try gate.begin(v.signed_request, peer: peer, now: v.now_ms, enrolled: key)
        XCTAssertThrowsError(try gate.consume(expired, peer: peer, now: v.signed_request.request.expires_at_ms))
        let wrongPeer = try gate.begin(v.signed_request, peer: peer, now: v.now_ms, enrolled: key)
        XCTAssertThrowsError(try gate.consume(wrongPeer, peer: UUID(), now: v.now_ms))
    }
    func testPrototypeGateRefusesLegitimatelySignedLogonOrRealAccount() throws {
        let v = try vector()
        let key = try P256.Signing.PrivateKey(rawRepresentation: decodeHex(v.computer_private_scalar_hex_SYNTHETIC, count: 32))
        for variant in 0..<3 {
            var signed = v.signed_request
            switch variant {
            case 0: signed.request.purpose = "logon"
            case 1: signed.request.account_sid = "S-1-5-21"
            default: signed.request.account_name = "Real account"
            }
            signed.signature = hex(try key.signature(for: signed.request.canonical()).rawRepresentation)
            try signed.validate(now: v.now_ms, enrolled: signed.computer_public_key)
            var gate = ApprovalGate()
            XCTAssertThrowsError(try gate.begin(signed, peer: UUID(), now: v.now_ms, enrolled: signed.computer_public_key))
        }
    }
}
