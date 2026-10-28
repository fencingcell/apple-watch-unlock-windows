// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit

public enum ProtocolError: Error { case invalid, missingBehavior, unpaired, stale }
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
    public func canonical() throws -> Data { throw ProtocolError.missingBehavior }
}
public struct SignedRequest: Codable, Equatable {
    public var request: LoginRequest
    public var computer_public_key: String
    public var signature: String
    public func validate(now: UInt64, enrolled: String? = nil) throws { throw ProtocolError.missingBehavior }
}
public struct SignedApproval: Codable {
    public var nonce: String
    public var request_hash: String
    public var watch_public_key: String
    public var signature: String
    public static func make(request: LoginRequest, key: P256.Signing.PrivateKey) throws -> SignedApproval { throw ProtocolError.missingBehavior }
}
public func decodeHex(_ value: String, count: Int) throws -> Data { throw ProtocolError.missingBehavior }
public func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
public func fingerprint(_ publicKey: String) throws -> String { throw ProtocolError.missingBehavior }
public struct Enrollment {
    public private(set) var key: String?
    public init(key: String? = nil) { self.key = key }
    public mutating func confirm(_ candidate: String, fingerprint: String) throws { throw ProtocolError.missingBehavior }
    public func require(_ candidate: String) throws { throw ProtocolError.missingBehavior }
}
public struct Frames {
    public init() {}
    public mutating func start(peer: UUID, now: UInt64) {}
    public mutating func append(_ frame: Data, peer: UUID, now: UInt64) throws -> Data? { throw ProtocolError.missingBehavior }
    public static func encode(_ payload: Data) throws -> [Data] { throw ProtocolError.missingBehavior }
}
public struct ApprovalGate {
    public init() {}
    public mutating func begin(_ request: SignedRequest, peer: UUID, now: UInt64, enrolled: String) throws -> UUID { throw ProtocolError.missingBehavior }
    public mutating func cancel() {}
    public mutating func consume(_ token: UUID, peer: UUID, now: UInt64) throws -> LoginRequest { throw ProtocolError.missingBehavior }
}
