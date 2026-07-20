import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'crypto_exception.dart';
import 'crypto_job.dart';
import 'crypto_progress.dart';
import 'src/crypto_channel.dart';
import 'src/method_channel_crypto.dart';

/// Public entry point for the native (Kotlin/Swift) hybrid RSA-OAEP-SHA256 +
/// AES-256-GCM encryption engine.
///
/// This is the only class app code should depend on; [CryptoChannel] is an
/// internal seam that exists purely so this facade can be unit-tested with
/// a fake channel instead of the real platform channel (dependency
/// inversion - see `test/` for an example fake).
///
/// All file/byte containers produced here follow the `ENCv1` format (see
/// the native `CryptoFormat` files) and can be decrypted by the companion
/// Python reference implementation and vice versa.
class SeroCrypto {
  final CryptoChannel _channel;

  /// Inject a fake [CryptoChannel] in tests; production code should just
  /// use the default constructor, e.g. as a singleton:
  /// `final crypto = SeroCrypto();`
  SeroCrypto({CryptoChannel? channel}) : _channel = channel ?? MethodChannelCrypto();

  final _random = Random.secure();

  String _newJobId() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return base64UrlEncode(bytes);
  }

  // --------------------------------------------------------------------
  // Key management
  // --------------------------------------------------------------------

  /// Generates a new RSA-2048 key pair on-device (Android Keystore /
  /// iOS Keychain - the private key never leaves secure storage in
  /// plaintext) and stores it under [alias]. Returns the DER-encoded
  /// (SubjectPublicKeyInfo) public key, which can be shared with a peer.
  Future<Uint8List> generateRSAKeyPair(String alias) async {
    final result = await _channel.invoke('generateRSAKeyPair', {'alias': alias});
    return base64Decode(result['publicKeyDer'] as String);
  }

  /// Imports a peer's RSA public key (DER SubjectPublicKeyInfo, e.g.
  /// produced by the Python tool or exported from another device) under
  /// [alias], for use with [encryptFile]/[encryptBytes].
  Future<void> importPublicKey(String alias, Uint8List publicKeyDer) async {
    await _channel.invoke('importPublicKey', {'alias': alias, 'publicKeyDer': publicKeyDer});
  }

  /// Imports an RSA private key (DER PKCS8, e.g. produced by the Python
  /// tool) under [alias], for use with [decryptFile]/[decryptBytes]. The
  /// key is stored wrapped at rest by a device-bound Keystore/Keychain key.
  Future<void> importPrivateKey(String alias, Uint8List privateKeyDer) async {
    await _channel.invoke('importPrivateKey', {'alias': alias, 'privateKeyDer': privateKeyDer});
  }

  /// Returns the DER-encoded (SubjectPublicKeyInfo) public key stored
  /// under [alias] - works for both generated and imported keys.
  Future<Uint8List> exportPublicKey(String alias) async {
    final result = await _channel.invoke('exportPublicKey', {'alias': alias});
    return base64Decode(result['publicKeyDer'] as String);
  }

  /// Permanently deletes the key pair stored under [alias].
  Future<void> deleteKey(String alias) async {
    await _channel.invoke('deleteKey', {'alias': alias});
  }

  // --------------------------------------------------------------------
  // File streaming (constant memory regardless of file size)
  // --------------------------------------------------------------------

  /// Encrypts the file at [inputPath] into [outputPath] using the RSA
  /// public key stored under [publicKeyAlias]. Streams in fixed-size
  /// chunks natively, so memory use is constant even for multi-gigabyte
  /// files. Returns a [CryptoJob] immediately; await `job.result` for
  /// completion, listen to `job.progress` for updates, and call
  /// `job.cancel()` to abort.
  CryptoJob encryptFile({
    required String inputPath,
    required String outputPath,
    required String publicKeyAlias,
  }) {
    return _runStreamingJob('encryptFile', {
      'inputPath': inputPath,
      'outputPath': outputPath,
      'publicKeyAlias': publicKeyAlias,
    });
  }

  /// Decrypts the file at [inputPath] (produced by [encryptFile] or the
  /// Python reference tool) into [outputPath] using the RSA private key
  /// stored under [privateKeyAlias]. Same streaming/progress/cancellation
  /// semantics as [encryptFile].
  CryptoJob decryptFile({
    required String inputPath,
    required String outputPath,
    required String privateKeyAlias,
  }) {
    return _runStreamingJob('decryptFile', {
      'inputPath': inputPath,
      'outputPath': outputPath,
      'privateKeyAlias': privateKeyAlias,
    });
  }

  CryptoJob _runStreamingJob(String method, Map<String, dynamic> args) {
    final jobId = _newJobId();
    final progress = _channel.progressStream
        .where((event) => event['jobId'] == jobId)
        .map(CryptoProgress.fromMap);

    final result = _channel.invoke(method, {...args, 'jobId': jobId}).then((map) => map['success'] == true);

    return CryptoJob(
      id: jobId,
      result: result,
      progress: progress,
      cancel: () async {
        await _channel.invoke('cancelJob', {'jobId': jobId});
      },
    );
  }

  // --------------------------------------------------------------------
  // In-memory bytes (small payloads only - no streaming/progress needed)
  // --------------------------------------------------------------------

  /// Encrypts [data] in memory using the RSA public key stored under
  /// [publicKeyAlias]. Intended for small payloads (tokens, messages,
  /// small blobs); for anything that might be large, prefer [encryptFile].
  Future<Uint8List> encryptBytes(Uint8List data, String publicKeyAlias) async {
    final result = await _channel.invoke('encryptBytes', {'data': data, 'publicKeyAlias': publicKeyAlias});
    return base64Decode(result['data'] as String);
  }

  /// Decrypts [data] (produced by [encryptBytes] or the Python reference
  /// tool) using the RSA private key stored under [privateKeyAlias].
  Future<Uint8List> decryptBytes(Uint8List data, String privateKeyAlias) async {
    final result = await _channel.invoke('decryptBytes', {'data': data, 'privateKeyAlias': privateKeyAlias});
    return base64Decode(result['data'] as String);
  }
}
