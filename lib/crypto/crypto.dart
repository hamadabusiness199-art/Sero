/// Native (Android Kotlin / iOS Swift) hybrid RSA-OAEP-SHA256 +
/// AES-256-GCM encryption engine for Flutter.
///
/// ```dart
/// import 'package:sero/crypto/crypto.dart';
///
/// final crypto = SeroCrypto();
///
/// // 1. Set up keys once.
/// await crypto.generateRSAKeyPair('me');               // local identity
/// await crypto.importPublicKey('bob', bobPublicKeyDer); // recipient
///
/// // 2. Encrypt a (potentially huge) file, with progress + cancellation.
/// final job = crypto.encryptFile(
///   inputPath: '/path/to/input.bin',
///   outputPath: '/path/to/output.encv1',
///   publicKeyAlias: 'bob',
/// );
/// job.progress.listen((p) => print('${((p.fraction ?? 0) * 100).toStringAsFixed(1)}%'));
/// final success = await job.result;
///
/// // 3. Decrypt it back (on Bob's device, using his private key alias).
/// final decryptJob = crypto.decryptFile(
///   inputPath: '/path/to/output.encv1',
///   outputPath: '/path/to/restored.bin',
///   privateKeyAlias: 'bob',
/// );
/// await decryptJob.result;
/// ```
library sero_crypto;

export 'crypto_exception.dart';
export 'crypto_job.dart';
export 'crypto_progress.dart';
export 'sero_crypto.dart';
