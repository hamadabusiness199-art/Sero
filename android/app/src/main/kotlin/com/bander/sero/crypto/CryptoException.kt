package com.bander.sero.crypto

/** Base type for every error the crypto engine can raise. Carries a stable
 * [code] so the Dart side can branch on failure kind without parsing strings. */
sealed class CryptoException(val code: String, message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    class InvalidFormat(message: String) : CryptoException("INVALID_FORMAT", message)
    class KeyNotFound(alias: String) : CryptoException("KEY_NOT_FOUND", "No key found for alias '$alias'")
    class KeyGenerationFailed(message: String, cause: Throwable? = null) :
        CryptoException("KEY_GENERATION_FAILED", message, cause)
    class EncryptionFailed(message: String, cause: Throwable? = null) :
        CryptoException("ENCRYPTION_FAILED", message, cause)
    class DecryptionFailed(message: String, cause: Throwable? = null) :
        CryptoException("DECRYPTION_FAILED", message, cause)
    class AuthenticationFailed(message: String = "GCM tag verification failed: data is corrupted or tampered") :
        CryptoException("AUTHENTICATION_FAILED", message)
    class IoFailure(message: String, cause: Throwable? = null) :
        CryptoException("IO_FAILURE", message, cause)
    class Cancelled(message: String = "Operation was cancelled") : CryptoException("CANCELLED", message)
    class InvalidArgument(message: String) : CryptoException("INVALID_ARGUMENT", message)
}
