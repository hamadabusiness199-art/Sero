import Foundation

/// Mirrors the Kotlin `CryptoException` hierarchy so the Dart side sees the
/// same stable error codes on both platforms.
enum CryptoError: Error, CustomNSError {
    case invalidFormat(String)
    case keyNotFound(String)
    case keyGenerationFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case authenticationFailed
    case ioFailure(String)
    case cancelled
    case invalidArgument(String)

    var code: String {
        switch self {
        case .invalidFormat: return "INVALID_FORMAT"
        case .keyNotFound: return "KEY_NOT_FOUND"
        case .keyGenerationFailed: return "KEY_GENERATION_FAILED"
        case .encryptionFailed: return "ENCRYPTION_FAILED"
        case .decryptionFailed: return "DECRYPTION_FAILED"
        case .authenticationFailed: return "AUTHENTICATION_FAILED"
        case .ioFailure: return "IO_FAILURE"
        case .cancelled: return "CANCELLED"
        case .invalidArgument: return "INVALID_ARGUMENT"
        }
    }

    var message: String {
        switch self {
        case .invalidFormat(let m): return m
        case .keyNotFound(let alias): return "No key found for alias '\(alias)'"
        case .keyGenerationFailed(let m): return m
        case .encryptionFailed(let m): return m
        case .decryptionFailed(let m): return m
        case .authenticationFailed: return "GCM tag verification failed: data is corrupted or tampered"
        case .ioFailure(let m): return m
        case .cancelled: return "Operation was cancelled"
        case .invalidArgument(let m): return m
        }
    }
}
