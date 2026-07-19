import Foundation
import Security

/// Cooperative cancellation flag checked between chunks of a streaming operation.
final class CancellationToken {
    private var _cancelled = false
    private let lock = NSLock()
    func cancel() { lock.lock(); _cancelled = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return _cancelled }
}

typealias ProgressCallback = (_ bytesProcessed: Int64, _ totalBytes: Int64) -> Void

/// Hybrid RSA-OAEP(SHA-256) + AES-256-GCM engine. Mirrors the Kotlin
/// `EncryptionEngine` exactly so the two platforms produce byte-identical
/// containers; see `CryptoFormat` for the shared layout.
///
/// All streaming methods use `InputStream`/`OutputStream` with a fixed-size
/// buffer (`CryptoFormat.streamBufferSize`), never loading a whole file into
/// memory, so RAM usage stays constant regardless of file size.
final class CryptoEngine {

    private let keyManager = KeychainKeyManager()

    // MARK: Key management

    func generateRSAKeyPair(alias: String) throws -> [UInt8] {
        try keyManager.generateKeyPair(alias: alias)
    }

    func importPublicKey(alias: String, spkiDer: [UInt8]) throws {
        try keyManager.importPublicKey(alias: alias, spkiDer: spkiDer)
    }

    func importPrivateKey(alias: String, pkcs8Der: [UInt8]) throws {
        try keyManager.importPrivateKey(alias: alias, pkcs8Der: pkcs8Der)
    }

    func exportPublicKey(alias: String) throws -> [UInt8] {
        try keyManager.exportPublicKeyDer(alias: alias)
    }

    func deleteKey(alias: String) {
        keyManager.deleteKeyPair(alias: alias)
    }

    // MARK: File streaming

    func encryptFile(inputPath: String, outputPath: String, publicKeyAlias: String,
                      token: CancellationToken, onProgress: ProgressCallback?) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: inputPath) else {
            throw CryptoError.ioFailure("Input file does not exist: \(inputPath)")
        }
        let totalBytes = (try? fm.attributesOfItem(atPath: inputPath)[.size] as? Int64) ?? 0

        let publicKey = try keyManager.getPublicKey(alias: publicKeyAlias)
        let aesKey = randomBytes(CryptoFormat.aesKeyLength)
        let iv = randomBytes(CryptoFormat.gcmIvLength)
        let encryptedAesKey = try rsaEncryptKey(aesKey, with: publicKey)

        guard let input = InputStream(fileAtPath: inputPath) else {
            throw CryptoError.ioFailure("Unable to open input file for reading")
        }
        let tmpPath = outputPath + ".tmp"
        fm.createFile(atPath: tmpPath, contents: nil)
        guard let output = OutputStream(toFileAtPath: tmpPath, append: false) else {
            throw CryptoError.ioFailure("Unable to open output file for writing")
        }
        input.open(); output.open()
        defer { input.close(); output.close() }

        do {
            try writeHeader(output, encryptedAesKey: encryptedAesKey, iv: iv)
            let cipher = try StreamingAESGCM(operation: CCOperation(kCCEncrypt), key: aesKey, iv: iv)
            try pump(input: input, output: output, totalBytes: totalBytes ?? 0,
                     token: token, onProgress: onProgress) { chunk in
                try cipher.update(chunk, isEncrypt: true)
            }
            let tag = try cipher.finalizeEncrypt()
            try write(output, tag)
            try moveIntoPlace(tmpPath: tmpPath, finalPath: outputPath)
        } catch {
            try? fm.removeItem(atPath: tmpPath)
            throw mapError(error, defaultCase: .encryptionFailed)
        }
    }

    func decryptFile(inputPath: String, outputPath: String, privateKeyAlias: String,
                      token: CancellationToken, onProgress: ProgressCallback?) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: inputPath) else {
            throw CryptoError.ioFailure("Input file does not exist: \(inputPath)")
        }
        let totalBytes = (try? fm.attributesOfItem(atPath: inputPath)[.size] as? Int64) ?? 0
        let privateKey = try keyManager.getPrivateKey(alias: privateKeyAlias)

        guard let input = InputStream(fileAtPath: inputPath) else {
            throw CryptoError.ioFailure("Unable to open input file for reading")
        }
        input.open()
        defer { input.close() }

        let (encryptedAesKey, iv) = try readHeader(input)
        let aesKey = try rsaDecryptKey(encryptedAesKey, with: privateKey)
        let headerSize = CryptoFormat.magicBytes.count + 4 + encryptedAesKey.count + CryptoFormat.gcmIvLength
        let ciphertextAndTagSize = (totalBytes ?? 0) - Int64(headerSize)
        let ciphertextSize = ciphertextAndTagSize - Int64(CryptoFormat.gcmTagLength)
        guard ciphertextSize >= 0 else {
            throw CryptoError.invalidFormat("File is smaller than the declared header")
        }

        let tmpPath = outputPath + ".tmp"
        fm.createFile(atPath: tmpPath, contents: nil)
        guard let output = OutputStream(toFileAtPath: tmpPath, append: false) else {
            throw CryptoError.ioFailure("Unable to open output file for writing")
        }
        output.open()
        defer { output.close() }

        do {
            let cipher = try StreamingAESGCM(operation: CCOperation(kCCDecrypt), key: aesKey, iv: iv)
            try pumpFixedLength(input: input, output: output, byteCount: ciphertextSize,
                                 totalBytes: totalBytes ?? 0, token: token, onProgress: onProgress) { chunk in
                try cipher.update(chunk, isEncrypt: false)
            }
            let tag = try readExactly(input, count: CryptoFormat.gcmTagLength)
            try cipher.finalizeDecrypt(expectedTag: tag)
            try moveIntoPlace(tmpPath: tmpPath, finalPath: outputPath)
        } catch {
            try? fm.removeItem(atPath: tmpPath)
            throw mapError(error, defaultCase: .decryptionFailed)
        }
    }

    // MARK: Bytes API (delegates to the same primitives as the file API)

    func encryptBytes(_ data: [UInt8], publicKeyAlias: String) throws -> [UInt8] {
        let publicKey = try keyManager.getPublicKey(alias: publicKeyAlias)
        let aesKey = randomBytes(CryptoFormat.aesKeyLength)
        let iv = randomBytes(CryptoFormat.gcmIvLength)
        let encryptedAesKey = try rsaEncryptKey(aesKey, with: publicKey)

        var out: [UInt8] = []
        out.append(contentsOf: CryptoFormat.magicBytes)
        out.append(contentsOf: uint32BE(encryptedAesKey.count))
        out.append(contentsOf: encryptedAesKey)
        out.append(contentsOf: iv)

        do {
            let cipher = try StreamingAESGCM(operation: CCOperation(kCCEncrypt), key: aesKey, iv: iv)
            var offset = 0
            while offset < data.count {
                let end = min(offset + CryptoFormat.streamBufferSize, data.count)
                out.append(contentsOf: try cipher.update(Array(data[offset..<end]), isEncrypt: true))
                offset = end
            }
            out.append(contentsOf: try cipher.finalizeEncrypt())
            return out
        } catch {
            throw mapError(error, defaultCase: .encryptionFailed)
        }
    }

    func decryptBytes(_ data: [UInt8], privateKeyAlias: String) throws -> [UInt8] {
        let privateKey = try keyManager.getPrivateKey(alias: privateKeyAlias)
        var offset = 0
        guard data.count >= CryptoFormat.magicBytes.count + 4 else {
            throw CryptoError.invalidFormat("Data too short to contain a header")
        }
        guard Array(data[0..<CryptoFormat.magicBytes.count]) == CryptoFormat.magicBytes else {
            throw CryptoError.invalidFormat("Unrecognized header; expected '\(CryptoFormat.magic)'")
        }
        offset = CryptoFormat.magicBytes.count
        let keyLen = Int(beUInt32(Array(data[offset..<offset + 4]))); offset += 4
        guard keyLen > 0, keyLen <= 4096, offset + keyLen + CryptoFormat.gcmIvLength <= data.count else {
            throw CryptoError.invalidFormat("Invalid encrypted key length in header")
        }
        let encryptedAesKey = Array(data[offset..<offset + keyLen]); offset += keyLen
        let iv = Array(data[offset..<offset + CryptoFormat.gcmIvLength]); offset += CryptoFormat.gcmIvLength

        let aesKey = try rsaDecryptKey(encryptedAesKey, with: privateKey)
        guard data.count - offset >= CryptoFormat.gcmTagLength else {
            throw CryptoError.invalidFormat("Data too short to contain a GCM tag")
        }
        let ciphertextEnd = data.count - CryptoFormat.gcmTagLength
        do {
            let cipher = try StreamingAESGCM(operation: CCOperation(kCCDecrypt), key: aesKey, iv: iv)
            var plain: [UInt8] = []
            var cur = offset
            while cur < ciphertextEnd {
                let end = min(cur + CryptoFormat.streamBufferSize, ciphertextEnd)
                plain.append(contentsOf: try cipher.update(Array(data[cur..<end]), isEncrypt: false))
                cur = end
            }
            let tag = Array(data[ciphertextEnd..<data.count])
            try cipher.finalizeDecrypt(expectedTag: tag)
            return plain
        } catch {
            throw mapError(error, defaultCase: .decryptionFailed)
        }
    }

    // MARK: RSA-OAEP-SHA256 (Security framework)

    private func rsaEncryptKey(_ aesKey: [UInt8], with publicKey: SecKey) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateEncryptedData(
            publicKey, .rsaEncryptionOAEPSHA256, Data(aesKey) as CFData, &error
        ) else {
            throw CryptoError.encryptionFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "RSA-OAEP encryption failed")
        }
        return [UInt8](result as Data)
    }

    private func rsaDecryptKey(_ encrypted: [UInt8], with privateKey: SecKey) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateDecryptedData(
            privateKey, .rsaEncryptionOAEPSHA256, Data(encrypted) as CFData, &error
        ) else {
            throw CryptoError.decryptionFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "RSA-OAEP decryption failed")
        }
        return [UInt8](result as Data)
    }

    // MARK: Streaming helpers

    private func writeHeader(_ output: OutputStream, encryptedAesKey: [UInt8], iv: [UInt8]) throws {
        try write(output, CryptoFormat.magicBytes)
        try write(output, uint32BE(encryptedAesKey.count))
        try write(output, encryptedAesKey)
        try write(output, iv)
    }

    private func readHeader(_ input: InputStream) throws -> ([UInt8], [UInt8]) {
        let magic = try readExactly(input, count: CryptoFormat.magicBytes.count)
        guard magic == CryptoFormat.magicBytes else {
            throw CryptoError.invalidFormat("Unrecognized file header; expected '\(CryptoFormat.magic)'")
        }
        let lenBytes = try readExactly(input, count: 4)
        let keyLen = Int(beUInt32(lenBytes))
        guard keyLen > 0, keyLen <= 4096 else {
            throw CryptoError.invalidFormat("Invalid encrypted key length in header: \(keyLen)")
        }
        let encryptedKey = try readExactly(input, count: keyLen)
        let iv = try readExactly(input, count: CryptoFormat.gcmIvLength)
        return (encryptedKey, iv)
    }

    /// Streams the remainder of `input` through `transform`, writing results to `output`.
    private func pump(input: InputStream, output: OutputStream, totalBytes: Int64,
                       token: CancellationToken, onProgress: ProgressCallback?,
                       transform: ([UInt8]) throws -> [UInt8]) throws {
        var buffer = [UInt8](repeating: 0, count: CryptoFormat.streamBufferSize)
        var processed: Int64 = 0
        while input.hasBytesAvailable {
            if token.isCancelled { throw CryptoError.cancelled }
            let read = buffer.withUnsafeMutableBytes { ptr in
                input.read(ptr.bindMemory(to: UInt8.self).baseAddress!, maxLength: CryptoFormat.streamBufferSize)
            }
            if read < 0 { throw CryptoError.ioFailure(input.streamError?.localizedDescription ?? "Read error") }
            if read == 0 { break }
            let chunk = Array(buffer[0..<read])
            try write(output, try transform(chunk))
            processed += Int64(read)
            onProgress?(processed, totalBytes)
        }
        onProgress?(max(processed, totalBytes), totalBytes)
    }

    /// Like `pump`, but stops after exactly `byteCount` input bytes (used for
    /// decryption, where the GCM tag trails the ciphertext in the same stream).
    private func pumpFixedLength(input: InputStream, output: OutputStream, byteCount: Int64, totalBytes: Int64,
                                  token: CancellationToken, onProgress: ProgressCallback?,
                                  transform: ([UInt8]) throws -> [UInt8]) throws {
        var buffer = [UInt8](repeating: 0, count: CryptoFormat.streamBufferSize)
        var remaining = byteCount
        var processed: Int64 = 0
        while remaining > 0 {
            if token.isCancelled { throw CryptoError.cancelled }
            let toRead = Int(min(Int64(CryptoFormat.streamBufferSize), remaining))
            let read = buffer.withUnsafeMutableBytes { ptr in
                input.read(ptr.bindMemory(to: UInt8.self).baseAddress!, maxLength: toRead)
            }
            if read <= 0 { throw CryptoError.invalidFormat("Unexpected end of stream while reading ciphertext") }
            let chunk = Array(buffer[0..<read])
            try write(output, try transform(chunk))
            remaining -= Int64(read)
            processed += Int64(read)
            onProgress?(processed, totalBytes)
        }
    }

    private func readExactly(_ input: InputStream, count: Int) throws -> [UInt8] {
        var result = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let read = result.withUnsafeMutableBytes { ptr -> Int in
                input.read(ptr.baseAddress!.advanced(by: offset), maxLength: count - offset)
            }
            if read <= 0 { throw CryptoError.invalidFormat("Unexpected end of stream while reading header") }
            offset += read
        }
        return result
    }

    private func write(_ output: OutputStream, _ bytes: [UInt8]) throws {
        guard !bytes.isEmpty else { return }
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBytes { ptr -> Int in
                output.write(ptr.bindMemory(to: UInt8.self).baseAddress!.advanced(by: offset), maxLength: bytes.count - offset)
            }
            if written <= 0 { throw CryptoError.ioFailure(output.streamError?.localizedDescription ?? "Write error") }
            offset += written
        }
    }

    private func moveIntoPlace(tmpPath: String, finalPath: String) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: finalPath) { try? fm.removeItem(atPath: finalPath) }
        try fm.moveItem(atPath: tmpPath, toPath: finalPath)
    }

    private func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }

    private func uint32BE(_ value: Int) -> [UInt8] {
        let v = UInt32(value)
        return [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }

    private func beUInt32(_ bytes: [UInt8]) -> UInt32 {
        (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
    }

    private func mapError(_ error: Error, defaultCase: (String) -> CryptoError) -> CryptoError {
        if let e = error as? CryptoError { return e }
        return defaultCase(error.localizedDescription)
    }
}
