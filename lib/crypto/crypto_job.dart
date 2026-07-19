import 'dart:async';

import 'crypto_progress.dart';

/// A handle to an in-flight `encryptFile`/`decryptFile` call.
///
/// ```dart
/// final job = crypto.encryptFile(
///   inputPath: input, outputPath: output, publicKeyAlias: 'recipient',
/// );
/// job.progress.listen((p) => print('${(p.fraction ?? 0) * 100}%'));
/// // Later, e.g. from a "Cancel" button:
/// await job.cancel();
/// await job.result; // throws CryptoException(cancelled) if cancel() won.
/// ```
class CryptoJob {
  final String id;

  /// Completes with `true`/`false`/error once the native side finishes.
  final Future<bool> result;

  /// Progress ticks scoped to this job only (already filtered by [id]).
  final Stream<CryptoProgress> progress;

  final Future<void> Function() _cancel;

  CryptoJob({
    required this.id,
    required this.result,
    required this.progress,
    required Future<void> Function() cancel,
  }) : _cancel = cancel;

  /// Requests cancellation. The native side checks for this between
  /// stream chunks, so cancellation is prompt but not necessarily
  /// instantaneous; await [result] to know when the job has actually
  /// stopped (it will complete with a [CryptoException] whose
  /// `isCancelled` is true).
  Future<void> cancel() => _cancel();
}
