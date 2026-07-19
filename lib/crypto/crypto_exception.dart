/// Stable error codes shared with the Android (`CryptoException.kt`) and
/// iOS (`CryptoError.swift`) native implementations.
enum CryptoErrorCode {
  invalidFormat,
  keyNotFound,
  keyGenerationFailed,
  encryptionFailed,
  decryptionFailed,
  authenticationFailed,
  ioFailure,
  cancelled,
  invalidArgument,
  unknown;

  static CryptoErrorCode fromWire(String? code) {
    switch (code) {
      case 'INVALID_FORMAT':
        return CryptoErrorCode.invalidFormat;
      case 'KEY_NOT_FOUND':
        return CryptoErrorCode.keyNotFound;
      case 'KEY_GENERATION_FAILED':
        return CryptoErrorCode.keyGenerationFailed;
      case 'ENCRYPTION_FAILED':
        return CryptoErrorCode.encryptionFailed;
      case 'DECRYPTION_FAILED':
        return CryptoErrorCode.decryptionFailed;
      case 'AUTHENTICATION_FAILED':
        return CryptoErrorCode.authenticationFailed;
      case 'IO_FAILURE':
        return CryptoErrorCode.ioFailure;
      case 'CANCELLED':
        return CryptoErrorCode.cancelled;
      case 'INVALID_ARGUMENT':
        return CryptoErrorCode.invalidArgument;
      default:
        return CryptoErrorCode.unknown;
    }
  }
}

/// Thrown by every [SeroCrypto] operation on failure. Carries a typed
/// [code] so callers can branch on failure kind (e.g. show "wrong key" for
/// [CryptoErrorCode.authenticationFailed]) without parsing message strings.
class CryptoException implements Exception {
  final CryptoErrorCode code;
  final String message;

  const CryptoException(this.code, this.message);

  /// True when decryption failed because the GCM authentication tag did not
  /// verify - i.e. the wrong key was used, or the data was corrupted/tampered.
  bool get isAuthenticationFailure => code == CryptoErrorCode.authenticationFailed;

  /// True when the operation was cancelled via [SeroCrypto.cancel].
  bool get isCancelled => code == CryptoErrorCode.cancelled;

  @override
  String toString() => 'CryptoException(${code.name}): $message';
}
