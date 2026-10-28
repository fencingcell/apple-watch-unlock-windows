// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit
import Security

enum WatchKeychain {
    private static let service = "org.watchlogin.prototype.watch.pairing.v1"
    private static func query(_ name: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: name, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
    }
    static func read(_ name: String) throws -> Data? {
        var q = query(name); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeychainFailure(status: status) }
        return data
    }
    static func store(_ data: Data, name: String) throws {
        let q = query(name)
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = q
            item.removeValue(forKey: kSecUseAuthenticationUI as String)
            attributes.forEach { item[$0.key] = $0.value }
            let added = SecItemAdd(item as CFDictionary, nil)
            guard added == errSecSuccess else { throw KeychainFailure(status: added) }
        } else if status != errSecSuccess { throw KeychainFailure(status: status) }
    }
    static func signingKey() throws -> P256.Signing.PrivateKey {
        if let raw = try read("signing-key") { return try P256.Signing.PrivateKey(rawRepresentation: raw) }
        let key = P256.Signing.PrivateKey()
        try store(key.rawRepresentation, name: "signing-key")
        return key
    }
    static func enrollment() throws -> Enrollment {
        guard let data = try read("computer-key") else { return Enrollment() }
        guard let key = String(data: data, encoding: .utf8) else { throw ProtocolError.invalid }
        _ = try fingerprint(key)
        return Enrollment(key: key)
    }
    static func revoke() throws {
        for name in ["computer-key", "signing-key"] {
            let status = SecItemDelete(query(name) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainFailure(status: status) }
        }
    }
}
struct KeychainFailure: Error { let status: OSStatus }
