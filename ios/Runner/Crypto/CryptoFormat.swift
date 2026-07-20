import Foundation

/// Binary container format shared with Android and the Python reference
/// implementation. See the Kotlin `CryptoFormat.kt` for the authoritative
/// description; kept in sync here.
///
///   [0..5)    "ENCv1"                      5 bytes
///   [5..7)    encryptedKeyLength (uint16BE) 2 bytes  - matches Python's struct.pack(">H", ...)
///   [7..7+N)  RSA-OAEP-SHA256(AES-256 key)  N bytes
///   [..+12)   GCM IV                        12 bytes
///   [..EOF)   AES-256-GCM ciphertext || 16-byte GCM tag
enum CryptoFormat {
    static let magic = "ENCv1"
    static let magicBytes: [UInt8] = Array(magic.utf8)

    static let gcmIvLength = 12
    static let gcmTagLength = 16
    static let aesKeyLength = 32     // AES-256
    static let rsaKeySizeBits = 2048

    /// Fixed streaming buffer size; memory usage never grows with file size.
    static let streamBufferSize = 8 * 1024 * 1024 // 8 MB
}