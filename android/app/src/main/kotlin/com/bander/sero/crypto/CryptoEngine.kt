package com.bander.sero.crypto

import android.content.Context
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.security.PrivateKey
import java.security.PublicKey
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cancellation token passed down into long-running streaming operations.
 * `EncryptionEngine` checks [isCancelled] between chunks so a job can be
 * aborted promptly without leaving partial output mid-write when possible.
 */
class CancellationToken {
    private val cancelled = AtomicBoolean(false)
    fun cancel() = cancelled.set(true)
    val isCancelled: Boolean get() = cancelled.get()
}

/** Reports streaming progress. Values are bytes processed / total bytes (total may be -1 if unknown). */
typealias ProgressCallback = (bytesProcessed: Long, totalBytes: Long) -> Unit

/**
 * Hybrid RSA-OAEP(SHA-256) + AES-256-GCM crypto engine.
 *
 * A fresh random AES-256 key is generated per encryption operation, used to
 * encrypt the payload with AES-GCM, and is itself protected with RSA-OAEP
 * using the recipient's public key. The container format is documented in
 * [CryptoFormat] and is binary-compatible with the companion Python
 * implementation.
 *
 * All streaming methods operate with a constant-size buffer
 * ([CryptoFormat.STREAM_BUFFER_SIZE]) regardless of input size, so memory
 * usage does not grow with file size (tested conceptually up to 20GB+;
 * throughput is bound by disk/IO, not RAM).
 */
class EncryptionEngine(context: Context) {

    private val keyStore = SecureKeyStore(context)
    private val secureRandom = SecureRandom()

    // ------------------------------------------------------------------
    // Key management (delegates to SecureKeyStore)
    // ------------------------------------------------------------------

    fun generateRSAKeyPair(alias: String): ByteArray = keyStore.generateKeyPair(alias).encoded

    fun importPublicKey(alias: String, spkiDer: ByteArray): Unit {
        keyStore.importPublicKey(alias, spkiDer)
    }

    fun importPrivateKey(alias: String, pkcs8Der: ByteArray): Unit {
        keyStore.importPrivateKey(alias, pkcs8Der)
    }

    fun exportPublicKey(alias: String): ByteArray = keyStore.exportPublicKeyDer(alias)

    fun deleteKey(alias: String) {
        keyStore.deleteKeystoreKey(alias)
        keyStore.deleteImportedKeys(alias)
    }

    // ------------------------------------------------------------------
    // File streaming API
    // ------------------------------------------------------------------

    fun encryptFile(
        inputPath: String,
        outputPath: String,
        publicKeyAlias: String,
        token: CancellationToken,
        onProgress: ProgressCallback?
    ) {
        val input = File(inputPath)
        if (!input.exists() || !input.isFile) {
            throw CryptoException.IoFailure("Input file does not exist: $inputPath")
        }
        val publicKey = keyStore.resolvePublicKey(publicKeyAlias)
        val totalBytes = input.length()

        val aesKey = generateAesKey()
        val encryptedAesKey = rsaEncryptKey(aesKey, publicKey)
        val iv = ByteArray(CryptoFormat.GCM_IV_LENGTH).also { secureRandom.nextBytes(it) }

        val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))

        var tmpOut: File? = null
        try {
            tmpOut = File(outputPath + ".tmp")
            BufferedInputStream(FileInputStream(input), CryptoFormat.STREAM_BUFFER_SIZE).use { rawIn ->
                BufferedOutputStream(FileOutputStream(tmpOut), CryptoFormat.STREAM_BUFFER_SIZE).use { rawOut ->
                    writeHeader(rawOut, encryptedAesKey, iv)
                    streamThroughCipher(rawIn, rawOut, cipher, totalBytes, token, onProgress)
                }
            }
            if (!tmpOut.renameTo(File(outputPath))) {
                tmpOut.copyTo(File(outputPath), overwrite = true)
                tmpOut.delete()
            }
        } catch (c: CryptoException.Cancelled) {
            tmpOut?.delete()
            throw c
        } catch (t: Throwable) {
            tmpOut?.delete()
            throw CryptoException.EncryptionFailed("File encryption failed", t)
        } finally {
            aesKey.destroyQuietly()
        }
    }

    fun decryptFile(
        inputPath: String,
        outputPath: String,
        privateKeyAlias: String,
        token: CancellationToken,
        onProgress: ProgressCallback?
    ) {
        val input = File(inputPath)
        if (!input.exists() || !input.isFile) {
            throw CryptoException.IoFailure("Input file does not exist: $inputPath")
        }
        val privateKey = keyStore.resolvePrivateKey(privateKeyAlias)
        val totalBytes = input.length()

        var tmpOut: File? = null
        try {
            BufferedInputStream(FileInputStream(input), CryptoFormat.STREAM_BUFFER_SIZE).use { rawIn ->
                val (encryptedAesKey, iv) = readHeader(rawIn)
                val aesKey = rsaDecryptKey(encryptedAesKey, privateKey)
                try {
                    val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))

                    tmpOut = File(outputPath + ".tmp")
                    val headerSize = CryptoFormat.MAGIC_BYTES.size + 2 + encryptedAesKey.size + CryptoFormat.GCM_IV_LENGTH
                    val ciphertextBytes = totalBytes - headerSize
                    BufferedOutputStream(FileOutputStream(tmpOut), CryptoFormat.STREAM_BUFFER_SIZE).use { rawOut ->
                        streamThroughCipher(rawIn, rawOut, cipher, ciphertextBytes, token, onProgress)
                    }
                    if (!tmpOut!!.renameTo(File(outputPath))) {
                        tmpOut!!.copyTo(File(outputPath), overwrite = true)
                        tmpOut!!.delete()
                    }
                } finally {
                    aesKey.destroyQuietly()
                }
            }
        } catch (c: CryptoException.Cancelled) {
            tmpOut?.delete()
            throw c
        } catch (e: AEADBadTagException) {
            tmpOut?.delete()
            throw CryptoException.AuthenticationFailed()
        } catch (e: CryptoException) {
            tmpOut?.delete()
            throw e
        } catch (t: Throwable) {
            tmpOut?.delete()
            throw CryptoException.DecryptionFailed("File decryption failed", t)
        }
    }

    // ------------------------------------------------------------------
    // In-memory bytes API (delegates to the same streaming core so byte
    // arrays and files are always processed identically)
    // ------------------------------------------------------------------

    fun encryptBytes(data: ByteArray, publicKeyAlias: String): ByteArray {
        val publicKey = keyStore.resolvePublicKey(publicKeyAlias)
        val aesKey = generateAesKey()
        val encryptedAesKey = rsaEncryptKey(aesKey, publicKey)
        val iv = ByteArray(CryptoFormat.GCM_IV_LENGTH).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))
        try {
            val out = ByteArrayOutputStream(data.size + 64)
            writeHeader(out, encryptedAesKey, iv)
            streamThroughCipher(ByteArrayInputStream(data), out, cipher, data.size.toLong(), CancellationToken(), null)
            return out.toByteArray()
        } catch (t: Throwable) {
            throw CryptoException.EncryptionFailed("Byte encryption failed", t)
        } finally {
            aesKey.destroyQuietly()
        }
    }

    fun decryptBytes(data: ByteArray, privateKeyAlias: String): ByteArray {
        val privateKey = keyStore.resolvePrivateKey(privateKeyAlias)
        try {
            val input = ByteArrayInputStream(data)
            val (encryptedAesKey, iv) = readHeader(input)
            val aesKey = rsaDecryptKey(encryptedAesKey, privateKey)
            try {
                val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))
                val out = ByteArrayOutputStream(maxOf(data.size - 64, 0))
                streamThroughCipher(input, out, cipher, input.available().toLong(), CancellationToken(), null)
                return out.toByteArray()
            } finally {
                aesKey.destroyQuietly()
            }
        } catch (e: AEADBadTagException) {
            throw CryptoException.AuthenticationFailed()
        } catch (e: CryptoException) {
            throw e
        } catch (t: Throwable) {
            throw CryptoException.DecryptionFailed("Byte decryption failed", t)
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private fun generateAesKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(CryptoFormat.AES_KEY_LENGTH * 8, secureRandom)
        return generator.generateKey()
    }

    private fun rsaEncryptKey(aesKey: SecretKey, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(CryptoFormat.RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(aesKey.encoded)
    }

    private fun rsaDecryptKey(encryptedKey: ByteArray, privateKey: PrivateKey): SecretKey {
        val cipher = Cipher.getInstance(CryptoFormat.RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val raw = cipher.doFinal(encryptedKey)
        return SecretKeySpec(raw, "AES")
    }

    private fun writeHeader(out: OutputStream, encryptedAesKey: ByteArray, iv: ByteArray) {
        out.write(CryptoFormat.MAGIC_BYTES)
        // NOTE: key-length field is 2 bytes (uint16, big-endian) to stay
        // binary-compatible with the Python reference tool, which writes it
        // with struct.pack(">H", ...). A 2048-bit RSA-OAEP ciphertext is
        // 256 bytes and a 4096-bit one is 512 bytes, both well under the
        // 65535 max of a uint16, so this comfortably covers real key sizes.
        out.write(shortToBigEndianBytes(encryptedAesKey.size))
        out.write(encryptedAesKey)
        out.write(iv)
    }

    /** Reads and validates the header, returning (encryptedAesKey, iv). */
    private fun readHeader(input: InputStream): Pair<ByteArray, ByteArray> {
        val magic = ByteArray(CryptoFormat.MAGIC_BYTES.size)
        readFully(input, magic)
        if (!magic.contentEquals(CryptoFormat.MAGIC_BYTES)) {
            throw CryptoException.InvalidFormat("Unrecognized file header; expected '${CryptoFormat.MAGIC}'")
        }
        val lenBytes = ByteArray(2)
        readFully(input, lenBytes)
        val keyLen = bigEndianBytesToShort(lenBytes)
        if (keyLen <= 0 || keyLen > 4096) {
            throw CryptoException.InvalidFormat("Invalid encrypted key length in header: $keyLen")
        }
        val encryptedKey = ByteArray(keyLen)
        readFully(input, encryptedKey)
        val iv = ByteArray(CryptoFormat.GCM_IV_LENGTH)
        readFully(input, iv)
        return encryptedKey to iv
    }

    /** Streams [input] through [cipher] into [output] using a fixed-size
     * buffer, invoking [onProgress] periodically. Throws [CryptoException.Cancelled]
     * if [token] is cancelled mid-stream. */
    private fun streamThroughCipher(
        input: InputStream,
        output: OutputStream,
        cipher: Cipher,
        totalBytes: Long,
        token: CancellationToken,
        onProgress: ProgressCallback?
    ) {
        val buffer = ByteArray(CryptoFormat.STREAM_BUFFER_SIZE)
        var processed = 0L
        while (true) {
            if (token.isCancelled) throw CryptoException.Cancelled()
            val read = input.read(buffer)
            if (read == -1) break
            val outChunk = cipher.update(buffer, 0, read)
            if (outChunk != null && outChunk.isNotEmpty()) output.write(outChunk)
            processed += read
            onProgress?.invoke(processed, totalBytes)
        }
        if (token.isCancelled) throw CryptoException.Cancelled()
        val finalChunk = cipher.doFinal()
        if (finalChunk.isNotEmpty()) output.write(finalChunk)
        onProgress?.invoke(totalBytes.coerceAtLeast(processed), totalBytes)
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read == -1) throw CryptoException.InvalidFormat("Unexpected end of stream while reading header")
            offset += read
        }
    }

    /** 2-byte big-endian encoding, matching Python's struct.pack(">H", ...). */
    private fun shortToBigEndianBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 8 and 0xFF).toByte(),
        (value and 0xFF).toByte()
    )

    private fun bigEndianBytesToShort(bytes: ByteArray): Int =
        ((bytes[0].toInt() and 0xFF) shl 8) or
                (bytes[1].toInt() and 0xFF)

    private fun SecretKey.destroyQuietly() {
        try { if (this is javax.security.auth.Destroyable && !this.isDestroyed) this.destroy() } catch (_: Throwable) {}
    }
}