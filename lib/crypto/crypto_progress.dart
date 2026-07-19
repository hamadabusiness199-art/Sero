/// A single progress tick for a running `encryptFile`/`decryptFile` job.
class CryptoProgress {
  /// Identifies which job this tick belongs to (see [SeroCrypto.encryptFile]).
  final String jobId;

  final int bytesProcessed;

  /// Total bytes expected, or -1 if unknown.
  final int totalBytes;

  const CryptoProgress({
    required this.jobId,
    required this.bytesProcessed,
    required this.totalBytes,
  });

  /// Fraction complete in `[0.0, 1.0]`, or null if [totalBytes] is unknown or zero.
  double? get fraction {
    if (totalBytes <= 0) return null;
    return (bytesProcessed / totalBytes).clamp(0.0, 1.0);
  }

  factory CryptoProgress.fromMap(Map<dynamic, dynamic> map) => CryptoProgress(
        jobId: map['jobId'] as String,
        bytesProcessed: (map['bytesProcessed'] as num).toInt(),
        totalBytes: (map['totalBytes'] as num).toInt(),
      );

  @override
  String toString() => 'CryptoProgress(jobId: $jobId, $bytesProcessed/$totalBytes)';
}
