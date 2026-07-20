import Foundation
import Security

/// Manages RSA key material using only Apple's Security framework / Keychain.
/// No OpenSSL or third-party crypto libraries are used.
///
/// Both keys generated on-device and keys imported from an external source
/// (e.g. produced by the Python reference tool) are stored as genuine
/// Keychain `SecKey` items, scoped to this app, protected while the device
/// is locked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and are never
/// synchronized to iCloud.
final class KeychainKeyManager {

    private static let tagPrefix = "com.bander.sero.crypto."

    // MARK: Generation

    @discardableResult
    func generateKeyPair(alias: String) throws -> [UInt8] {
        deleteKeyPair(alias: alias) // ensure a clean slate for this alias

        let privateTag = tag(alias, isPrivate: true)
        let publicTag = tag(alias, isPrivate: false)

        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: privateTag,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: CryptoFormat.rsaKeySizeBits,
            kSecPrivateKeyAttrs as String: privateKeyAttrs
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CryptoError.keyGenerationFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "SecKeyCreateRandomKey failed")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CryptoError.keyGenerationFailed("Unable to derive public key")
        }
        // Persist the public key as its own permanent Keychain item too, so it
        // can be looked up independently (e.g. for exportPublicKey).
        try persistPublicKey(publicKey, tag: publicTag)

        return try spkiBytes(from: publicKey)
    }

    // MARK: Import

    func importPublicKey(alias: String, spkiDer: [UInt8]) throws {
        let pkcs1 = try DER.spkiToPKCS1PublicKey(spkiDer)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: CryptoFormat.rsaKeySizeBits
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(Data(pkcs1) as CFData, attrs as CFDictionary, &error) else {
            throw CryptoError.invalidArgument((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Invalid RSA public key")
        }
        try persistPublicKey(publicKey, tag: tag(alias, isPrivate: false))
    }

    func importPrivateKey(alias: String, pkcs8Der: [UInt8]) throws {
        let pkcs1 = try DER.pkcs8ToPKCS1PrivateKey(pkcs8Der)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: CryptoFormat.rsaKeySizeBits,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag(alias, isPrivate: true),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var error: Unmanaged<CFError>?
        // Creating with kSecAttrIsPermanent persists it to the Keychain as a side effect.
        guard let privateKey = SecKeyCreateWithData(Data(pkcs1) as CFData, attrs as CFDictionary, &error) else {
            throw CryptoError.invalidArgument((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Invalid RSA private key")
        }
        if let publicKey = SecKeyCopyPublicKey(privateKey) {
            try? persistPublicKey(publicKey, tag: tag(alias, isPrivate: false))
        }
    }

    // MARK: Export / lookup

    func exportPublicKeyDer(alias: String) throws -> [UInt8] {
        let key = try getPublicKey(alias: alias)
        return try spkiBytes(from: key)
    }

    func getPublicKey(alias: String) throws -> SecKey {
        try lookupKey(tag: tag(alias, isPrivate: false), keyClass: kSecAttrKeyClassPublic)
    }

    func getPrivateKey(alias: String) throws -> SecKey {
        try lookupKey(tag: tag(alias, isPrivate: true), keyClass: kSecAttrKeyClassPrivate)
    }

    func deleteKeyPair(alias: String) {
        for isPrivate in [true, false] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag(alias, isPrivate: isPrivate)
            ]
            SecItemDelete(query as CFDictionary)
        }
    }

    // MARK: Internals

    private func persistPublicKey(_ key: SecKey, tag: Data) throws {
        // Remove any existing item with this tag first (SecKeyCreateWithData
        // with kSecAttrIsPermanent errors if a duplicate already exists).
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsPermanent as String: true
        ]
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &error) else {
            throw CryptoError.keyGenerationFailed("Unable to read public key bytes")
        }
        guard SecKeyCreateWithData(raw, attrs as CFDictionary, &error) != nil else {
            throw CryptoError.keyGenerationFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unable to persist public key")
        }
    }

    private func lookupKey(tag: Data, keyClass: CFString) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: keyClass,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            throw CryptoError.keyNotFound(String(data: tag, encoding: .utf8) ?? "unknown")
        }
        return (key as! SecKey)
    }

    private func spkiBytes(from publicKey: SecKey) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw CryptoError.keyGenerationFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unable to export public key")
        }
        let pkcs1 = [UInt8](raw as Data)
        return DER.pkcs1PublicKeyToSPKI(pkcs1)
    }

    private func tag(_ alias: String, isPrivate: Bool) -> Data {
        Data((Self.tagPrefix + alias + (isPrivate ? ".private" : ".public")).utf8)
    }
}
