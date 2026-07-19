import 'dart:typed_data';

/// Abstracts the native transport so [SeroCrypto] can be unit-tested with a
/// fake implementation instead of the real platform channel.
abstract class CryptoChannel {
  Stream<Map<dynamic, dynamic>> get progressStream;

  Future<Map<dynamic, dynamic>> invoke(String method, Map<String, dynamic> args);
}
