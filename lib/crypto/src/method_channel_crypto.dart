import 'package:flutter/services.dart';

import 'crypto_channel.dart';
import '../crypto_exception.dart';

/// Real, platform-backed [CryptoChannel]. Talks to the native Kotlin/Swift
/// crypto engines over a `MethodChannel` (requests) and an `EventChannel`
/// (streaming progress), matching `CryptoPlugin.kt` / `CryptoPlugin.swift`.
class MethodChannelCrypto implements CryptoChannel {
  static const MethodChannel _methods = MethodChannel('sero/crypto/methods');
  static const EventChannel _progress = EventChannel('sero/crypto/progress');

  Stream<Map<dynamic, dynamic>>? _progressStream;

  @override
  Stream<Map<dynamic, dynamic>> get progressStream {
    return _progressStream ??= _progress
        .receiveBroadcastStream()
        .map((event) => event as Map<dynamic, dynamic>)
        .asBroadcastStream();
  }

  @override
  Future<Map<dynamic, dynamic>> invoke(String method, Map<String, dynamic> args) async {
    try {
      final result = await _methods.invokeMethod(method, args);
      return (result as Map<dynamic, dynamic>?) ?? const {};
    } on PlatformException catch (e) {
      throw CryptoException(CryptoErrorCode.fromWire(e.code), e.message ?? 'Unknown native error');
    } on MissingPluginException {
      throw const CryptoException(
        CryptoErrorCode.unknown,
        'Native crypto plugin is not registered on this platform. '
        'SeroCrypto currently supports Android and iOS only.',
      );
    }
  }
}
