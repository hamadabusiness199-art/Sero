import Foundation

/// A tiny, purpose-built DER (ASN.1) encoder/decoder.
///
/// `SecKeyCopyExternalRepresentation` returns RSA keys in raw **PKCS#1**
/// form (`RSAPublicKey` / `RSAPrivateKey` SEQUENCE), while Android's JCA and
/// Python's `cryptography`/PyCryptodome libraries default to the standard
/// **SubjectPublicKeyInfo** (SPKI) wrapper for public keys and **PKCS#8**
/// wrapper for private keys. This file bridges the two so the exact same
/// DER bytes can be exchanged across all three platforms without a full
/// ASN.1 library (no third-party dependency needed for such a small,
/// fixed-shape task).
enum DER {

    // rsaEncryption OID (1.2.840.113549.1.1.1) + NULL parameters, as used by
    // both the SPKI AlgorithmIdentifier and the PKCS8 PrivateKeyAlgorithm field.
    private static let rsaAlgorithmIdentifier: [UInt8] = [
        0x30, 0x0D,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        0x05, 0x00
    ]

    // MARK: Encoding primitives

    private static func length(_ len: Int) -> [UInt8] {
        if len < 0x80 { return [UInt8(len)] }
        var bytes: [UInt8] = []
        var value = len
        while value > 0 { bytes.insert(UInt8(value & 0xFF), at: 0); value >>= 8 }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    private static func sequence(_ content: [UInt8]) -> [UInt8] { tlv(0x30, content) }

    /// BIT STRING wrapping a byte string that already represents whole octets.
    private static func bitString(_ content: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + content) }

    /// OCTET STRING wrapping raw bytes.
    private static func octetString(_ content: [UInt8]) -> [UInt8] { tlv(0x04, content) }

    /// INTEGER 0, used as the PKCS8 version field.
    private static let integerZero: [UInt8] = [0x02, 0x01, 0x00]

    // MARK: Public key: PKCS1 RSAPublicKey -> SubjectPublicKeyInfo

    static func pkcs1PublicKeyToSPKI(_ pkcs1: [UInt8]) -> [UInt8] {
        sequence(rsaAlgorithmIdentifier + bitString(pkcs1))
    }

    /// Extracts the inner PKCS1 RSAPublicKey bytes from a SubjectPublicKeyInfo DER blob.
    static func spkiToPKCS1PublicKey(_ spki: [UInt8]) throws -> [UInt8] {
        var reader = Reader(spki)
        let outer = try reader.readTLV(expectedTag: 0x30) // SEQUENCE
        var inner = Reader(outer)
        _ = try inner.readTLV(expectedTag: 0x30) // AlgorithmIdentifier (skipped)
        let bitStringContent = try inner.readTLV(expectedTag: 0x03) // BIT STRING
        guard let first = bitStringContent.first, first == 0x00 else {
            throw CryptoError.invalidFormat("Malformed SubjectPublicKeyInfo: unexpected BIT STRING padding")
        }
        return Array(bitStringContent.dropFirst())
    }

    // MARK: Private key: PKCS1 RSAPrivateKey -> PKCS8

    static func pkcs1PrivateKeyToPKCS8(_ pkcs1: [UInt8]) -> [UInt8] {
        sequence(integerZero + rsaAlgorithmIdentifier + octetString(pkcs1))
    }

    /// Extracts the inner PKCS1 RSAPrivateKey bytes from a PKCS8 DER blob.
    /// If the input is already a bare PKCS1 key (starts with a SEQUENCE whose
    /// first element is an INTEGER 0 followed directly by more INTEGERs
    /// rather than an AlgorithmIdentifier SEQUENCE), it is returned as-is.
    static func pkcs8ToPKCS1PrivateKey(_ der: [UInt8]) throws -> [UInt8] {
        var reader = Reader(der)
        let outer = try reader.readTLV(expectedTag: 0x30) // SEQUENCE
        var inner = Reader(outer)
        let version = try inner.readTLV(expectedTag: 0x02) // INTEGER (version)
        guard version == [0x00] else {
            throw CryptoError.invalidFormat("Unsupported PKCS8 version")
        }
        // Peek: if the next TLV is a SEQUENCE, this is a proper PKCS8 blob.
        guard let nextTag = inner.peekTag() else {
            throw CryptoError.invalidFormat("Malformed PKCS8 private key")
        }
        if nextTag == 0x30 {
            _ = try inner.readTLV(expectedTag: 0x30) // AlgorithmIdentifier (skipped)
            return try inner.readTLV(expectedTag: 0x04) // OCTET STRING containing PKCS1 bytes
        }
        // Not PKCS8 - caller passed a bare PKCS1 key; return the whole thing unchanged.
        return der
    }

    // MARK: Minimal DER reader

    private struct Reader {
        private let bytes: [UInt8]
        private var offset: Int = 0
        init(_ bytes: [UInt8]) { self.bytes = bytes }

        func peekTag() -> UInt8? { offset < bytes.count ? bytes[offset] : nil }

        mutating func readTLV(expectedTag: UInt8) throws -> [UInt8] {
            guard offset < bytes.count, bytes[offset] == expectedTag else {
                throw CryptoError.invalidFormat("Unexpected DER tag while parsing key")
            }
            offset += 1
            guard offset < bytes.count else { throw CryptoError.invalidFormat("Truncated DER data") }
            var len = Int(bytes[offset]); offset += 1
            if len & 0x80 != 0 {
                let numBytes = len & 0x7F
                guard numBytes > 0, offset + numBytes <= bytes.count else {
                    throw CryptoError.invalidFormat("Truncated DER length")
                }
                len = 0
                for _ in 0..<numBytes { len = (len << 8) | Int(bytes[offset]); offset += 1 }
            }
            guard offset + len <= bytes.count else { throw CryptoError.invalidFormat("Truncated DER content") }
            let content = Array(bytes[offset..<offset + len])
            offset += len
            return content
        }
    }
}
