import Foundation

/// Constant-memory AES-256-GCM streaming cipher built on Apple's CommonCrypto.
///
/// Uses the incremental GCM entry points (`CCCryptorGCMSetIV`,
/// `CCCryptorGCMEncrypt`/`Decrypt`, `CCCryptorGCMFinalize`) declared in
/// `CommonCryptoGCM.h`. These ship inside CommonCrypto on every iOS release
/// since iOS 11 and produce output byte-identical to a standard single-pass
/// AES-256-GCM implementation (e.g. PyCryptodome / `cryptography` on
/// Python, or `javax.crypto.Cipher` on Android): ciphertext followed by a
/// 16-byte authentication tag, with no additional framing.
///
/// NOTE ON APP STORE REVIEW: `CCCryptorGCMSetIV`/`CCCryptorGCMFinalize` are
/// not declared in the public CommonCrypto umbrella header (they are
/// documented "SPI"), even though they ship in every OS build. Some third
/// party SDKs using the older sibling symbols have been flagged by App
/// Store static analysis in the past. If this ships to the App Store,
/// validate with a TestFlight build first; if Apple's review tooling ever
/// flags these symbols, the fallback is to switch this file to a chunked
/// CryptoKit `AES.GCM` scheme with a custom multi-tag container (see the
/// project README for the trade-offs of that alternative).
final class StreamingAESGCM {

    private var cryptorRef: CCCryptorRef?
    private let bufferOut: UnsafeMutablePointer<UInt8>
    private let bufferCapacity: Int

    init(operation: CCOperation, key: [UInt8], iv: [UInt8]) throws {
        bufferCapacity = CryptoFormat.streamBufferSize
        bufferOut = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferCapacity)

        var ref: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyPtr in
            CCCryptorCreateWithMode(
                operation,
                CCMode(kCCModeGCM),
                CCAlgorithm(kCCAlgorithmAES),
                CCPadding(ccNoPadding),
                nil, keyPtr.baseAddress, key.count,
                nil, 0, 0,
                CCModeOptions(),
                &ref
            )
        }
        guard createStatus == kCCSuccess, let cryptor = ref else {
            bufferOut.deallocate()
            throw CryptoError.encryptionFailed("Failed to create AES-GCM cryptor (status \(createStatus))")
        }
        self.cryptorRef = cryptor

        let ivStatus = iv.withUnsafeBytes { ivPtr in
            CCCryptorGCMSetIV(cryptor, ivPtr.baseAddress, iv.count)
        }
        guard ivStatus == kCCSuccess else {
            CCCryptorRelease(cryptor)
            bufferOut.deallocate()
            throw CryptoError.encryptionFailed("Failed to set GCM IV (status \(ivStatus))")
        }
    }

    deinit {
        if let cryptor = cryptorRef { CCCryptorRelease(cryptor) }
        bufferOut.deallocate()
    }

    /// Processes one chunk of input, returning the transformed bytes.
    /// GCM is a stream cipher internally, so output length always equals
    /// input length (no block-padding to account for).
    func update(_ input: [UInt8], isEncrypt: Bool) throws -> [UInt8] {
        guard let cryptor = cryptorRef else { throw CryptoError.encryptionFailed("Cryptor already finalized") }
        guard input.count <= bufferCapacity else {
            throw CryptoError.encryptionFailed("Chunk exceeds internal buffer capacity")
        }
        if input.isEmpty { return [] }
        let status = input.withUnsafeBytes { inPtr -> CCCryptorStatus in
            isEncrypt
                ? CCCryptorGCMEncrypt(cryptor, inPtr.baseAddress, input.count, bufferOut)
                : CCCryptorGCMDecrypt(cryptor, inPtr.baseAddress, input.count, bufferOut)
        }
        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed("GCM \(isEncrypt ? "encrypt" : "decrypt") failed (status \(status))")
        }
        return Array(UnsafeBufferPointer(start: bufferOut, count: input.count))
    }

    /// Finalizes encryption, returning the 16-byte authentication tag.
    func finalizeEncrypt() throws -> [UInt8] {
        guard let cryptor = cryptorRef else { throw CryptoError.encryptionFailed("Cryptor already finalized") }
        var tag = [UInt8](repeating: 0, count: CryptoFormat.gcmTagLength)
        let status = tag.withUnsafeMutableBytes { tagPtr in
            CCCryptorGCMFinalize(cryptor, tagPtr.baseAddress, CryptoFormat.gcmTagLength)
        }
        CCCryptorRelease(cryptor)
        cryptorRef = nil
        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed("GCM finalize failed (status \(status))")
        }
        return tag
    }

    /// Finalizes decryption, verifying the provided tag. Throws
    /// `CryptoError.authenticationFailed` if the tag does not match.
    func finalizeDecrypt(expectedTag: [UInt8]) throws {
        guard let cryptor = cryptorRef else { throw CryptoError.encryptionFailed("Cryptor already finalized") }
        var tag = expectedTag
        let status = tag.withUnsafeMutableBytes { tagPtr in
            CCCryptorGCMFinalize(cryptor, tagPtr.baseAddress, tag.count)
        }
        CCCryptorRelease(cryptor)
        cryptorRef = nil
        guard status == kCCSuccess else {
            throw CryptoError.authenticationFailed
        }
    }
}
