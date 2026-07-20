package com.bander.sero.crypto

/**
 * Binary container format shared with the Python reference implementation.
 *
 * Layout (all integers big-endian):
 *
 *   [0..5)    "ENCv1"                      5 bytes  - magic / version header
 *   [5..7)    encryptedKeyLength (uint16)  2 bytes  - matches Python's struct.pack(">H", ...)
 *   [7..7+N)  RSA-OAEP-SHA256(AES-256 key) N bytes  - N == encryptedKeyLength
 *   [..+12)   GCM IV                       12 bytes - fresh random per file
 *   [..EOF)   AES-256-GCM ciphertext       ciphertext || 16-byte GCM tag
 *
 * The GCM tag is NOT written separately: both javax.crypto.Cipher (Android)
 * and CommonCrypto's incremental GCM (iOS) append the 16-byte authentication
 * tag to the output of the final encryption call, which is exactly what
 * PyCryptodome / `cryptography` produce on the Python side when the tag is
 * concatenated to the ciphertext. This keeps the three implementations
 * byte-for-byte compatible without any extra framing.
 */
object CryptoFormat {
    const val MAGIC = "ENCv1"
    val MAGIC_BYTES: ByteArray = MAGIC.toByteArray(Charsets.US_ASCII)

    const val GCM_IV_LENGTH = 12          // bytes
    const val GCM_TAG_LENGTH = 16         // bytes
    const val GCM_TAG_LENGTH_BITS = GCM_TAG_LENGTH * 8

    const val AES_KEY_LENGTH = 32         // AES-256
    const val RSA_KEY_SIZE = 2048         // bits, matches typical Python OAEP key size

    /** Size of the streaming read/write buffer. Chosen to keep memory usage
     * constant regardless of file size while still giving good throughput. */
    const val STREAM_BUFFER_SIZE = 8 * 1024 * 1024 // 8 MB

    const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
}