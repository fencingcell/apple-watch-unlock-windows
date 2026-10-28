// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit

public enum ProtocolError: Error { case invalid, unpaired, stale }
public struct LoginRequest: Codable, Equatable {
    public var protocol_version: UInt8
    public var purpose: String
    public var computer_id: String
    public var account_sid: String
    public var session_id: UInt32
    public var nonce: String
    public var expires_at_ms: UInt64
    public var computer_name: String
    public var account_name: String
    public func canonical() throws -> Data {
        guard protocol_version == 1, purpose == "probe" || purpose == "logon" else { throw ProtocolError.invalid }
        try validateText(account_sid, max: 184)
        let parts = account_sid.split(separator: "-", omittingEmptySubsequences: false)
        guard (4...18).contains(parts.count), parts[0] == "S", parts[1] == "1" else { throw ProtocolError.invalid }
        for (index, part) in parts.enumerated().dropFirst(2) {
            guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }),
                  let number = UInt64(part), number <= (index == 2 ? 281474976710655 : UInt64(UInt32.max)) else { throw ProtocolError.invalid }
        }
        try validateText(computer_name, max: 80)
        try validateText(account_name, max: 80)
        var bytes = Data("WATCH-LOGIN-REQUEST-V1\0".utf8)
        bytes.append(contentsOf: [protocol_version, purpose == "probe" ? 0 : 1])
        bytes.append(try decodeHex(computer_id, count: 32))
        appendText(account_sid, to: &bytes)
        appendBE(session_id, to: &bytes)
        bytes.append(try decodeHex(nonce, count: 32))
        appendBE(expires_at_ms, to: &bytes)
        appendText(computer_name, to: &bytes)
        appendText(account_name, to: &bytes)
        return bytes
    }
}
public struct SignedRequest: Codable, Equatable {
    public var request: LoginRequest
    public var computer_public_key: String
    public var signature: String
    public func validate(now: UInt64, enrolled: String? = nil) throws {
        let bytes = try request.canonical()
        guard request.expires_at_ms > now, request.expires_at_ms - now <= 30000,
              try fingerprint(computer_public_key) == request.computer_id else { throw ProtocolError.invalid }
        if let enrolled, enrolled != computer_public_key { throw ProtocolError.unpaired }
        let key = try P256.Signing.PublicKey(x963Representation: decodeHex(computer_public_key, count: 65))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: decodeHex(signature, count: 64))
        guard key.isValidSignature(signature, for: bytes) else { throw ProtocolError.invalid }
    }
}
public struct SignedApproval: Codable {
    public var nonce: String
    public var request_hash: String
    public var watch_public_key: String
    public var signature: String
    public static func make(request: LoginRequest, key: P256.Signing.PrivateKey) throws -> SignedApproval {
        let digest = Data(SHA256.hash(data: try request.canonical()))
        var bytes = Data("WATCH-LOGIN-APPROVAL-V1\0".utf8); bytes.append(digest)
        return SignedApproval(nonce: request.nonce, request_hash: hex(digest), watch_public_key: hex(key.publicKey.x963Representation), signature: hex(try key.signature(for: bytes).rawRepresentation))
    }
}
public func decodeHex(_ value: String, count: Int) throws -> Data {
    let ascii = Array(value.utf8)
    guard ascii.count == count * 2, ascii.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw ProtocolError.invalid }
    func digit(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
    return Data(stride(from: 0, to: ascii.count, by: 2).map { digit(ascii[$0]) * 16 + digit(ascii[$0+1]) })
}
public func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
public func fingerprint(_ publicKey: String) throws -> String {
    let bytes = try decodeHex(publicKey, count: 65)
    guard bytes.first == 4 else { throw ProtocolError.invalid }
    _ = try P256.Signing.PublicKey(x963Representation: bytes)
    return hex(Data(SHA256.hash(data: bytes)))
}
public struct Enrollment {
    public private(set) var key: String?
    public init(key: String? = nil) { self.key = key }
    public mutating func confirm(_ candidate: String, fingerprint: String) throws {
        guard try WatchLoginFingerprint(candidate) == fingerprint else { throw ProtocolError.invalid }
        key = candidate
    }
    public func require(_ candidate: String) throws {
        guard key == candidate else { throw ProtocolError.unpaired }
    }
}
public struct Frames {
    private var peer: UUID?
    private var started: UInt64 = 0
    private var total: Int?
    private var data = Data()
    public init() {}
    public mutating func start(peer: UUID, now: UInt64) { self.peer = peer; started = now; total = nil; data = Data() }
    public mutating func append(_ frame: Data, peer: UUID, now: UInt64) throws -> Data? {
        do {
            guard self.peer == peer, now >= started, now - started < 30000, (5...20).contains(frame.count) else { throw ProtocolError.invalid }
            let b = Array(frame)
            let offset = Int(b[0]) * 256 + Int(b[1]); let size = Int(b[2]) * 256 + Int(b[3])
            guard (1...4096).contains(size), offset == data.count, total == nil || total == size,
                  data.count + frame.count - 4 <= size else { throw ProtocolError.invalid }
            total = size; data.append(contentsOf: b.dropFirst(4))
            if data.count == size { self.peer = nil; return data }
            return nil
        } catch { self.peer = nil; total = nil; data.removeAll(); throw error }
    }
    public static func encode(_ payload: Data) throws -> [Data] {
        guard (1...4096).contains(payload.count) else { throw ProtocolError.invalid }
        return stride(from: 0, to: payload.count, by: 16).map { offset in
            var frame = Data(); appendBE(UInt16(offset), to: &frame); appendBE(UInt16(payload.count), to: &frame)
            frame.append(payload.subdata(in: offset..<min(offset + 16, payload.count))); return frame
        }
    }
}
public struct ApprovalGate {
    private var pending: (UUID, UUID, SignedRequest, String)?
    public init() {}
    public mutating func begin(_ request: SignedRequest, peer: UUID, now: UInt64, enrolled: String) throws -> UUID {
        pending = nil
        try request.validate(now: now, enrolled: enrolled)
        guard request.request.purpose == "probe", request.request.account_sid == "S-1-0-0", request.request.account_name == "Authentication test" else { throw ProtocolError.invalid }
        let token = UUID(); pending = (token, peer, request, enrolled); return token
    }
    public mutating func cancel() { pending = nil }
    public mutating func consume(_ token: UUID, peer: UUID, now: UInt64) throws -> LoginRequest {
        guard let saved = pending, saved.0 == token, saved.1 == peer else { throw ProtocolError.stale }
        pending = nil
        try saved.2.validate(now: now, enrolled: saved.3)
        return saved.2.request
    }
}

private func WatchLoginFingerprint(_ key: String) throws -> String { try fingerprint(key) }
private func validateText(_ text: String, max: Int) throws {
    guard !text.isEmpty, text.utf8.count <= max,
          !text.unicodeScalars.contains(where: { $0.value < 32 || (127...159).contains($0.value) }) else { throw ProtocolError.invalid }
}
private func appendBE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var big = value.bigEndian; withUnsafeBytes(of: &big) { data.append(contentsOf: $0) }
}
private func appendText(_ text: String, to data: inout Data) {
    appendBE(UInt16(text.utf8.count), to: &data); data.append(contentsOf: text.utf8)
}
