# Sero Native Encryption Engine

A production-oriented, native (no Flutter crypto packages) hybrid
**RSA-OAEP-SHA256 + AES-256-GCM** encryption engine for Android (Kotlin) and
iOS (Swift), exposed to Dart via `MethodChannel`/`EventChannel`, with a file
format that is byte-compatible with a companion Python implementation.

## Why MethodChannel instead of Pigeon

Pigeon needs a `dart run pigeon` codegen step (from `pub.dev`), which the
sandbox this was built in cannot reach. The channel names/payloads below are
written to be a drop-in target for Pigeon later if you want type-safe
codegen: each method takes a flat map of primitives/bytes and returns a flat
map, which is exactly what Pigeon generates under the hood.

## Architecture

```
lib/crypto/
  crypto.dart                 barrel export
  sero_crypto.dart            public facade (SeroCrypto) - the only class app code touches
  crypto_job.dart             cancellable/observable handle for streaming file jobs
  crypto_progress.dart        progress tick model
  crypto_exception.dart       typed error codes, shared with both native sides
  src/
    crypto_channel.dart       CryptoChannel interface (DI seam for testing)
    method_channel_crypto.dart real MethodChannel/EventChannel implementation

android/app/src/main/kotlin/com/bander/sero/crypto/
  CryptoFormat.kt              shared container format + constants
  CryptoException.kt           typed errors
  SecureKeyStore.kt            RSA key management (Android Keystore)
  CryptoEngine.kt              RSA-OAEP + AES-GCM streaming core
  CryptoPlugin.kt              FlutterPlugin: MethodChannel + EventChannel wiring

ios/Runner/Crypto/
  CryptoFormat.swift, CryptoError.swift    mirrors of the Kotlin files above
  DER.swift                    PKCS1 <-> SPKI/PKCS8 DER conversion (no 3rd-party ASN.1 lib)
  KeychainKeyManager.swift     RSA key management (Keychain / Security framework)
  CommonCryptoGCM.h            re-declares CommonCryptor's incremental GCM entry points
  StreamingAESGCM.swift        constant-memory AES-256-GCM streaming wrapper
  CryptoEngine.swift           RSA-OAEP + AES-GCM streaming core
  CryptoPlugin.swift           FlutterPlugin: MethodChannel + EventChannel wiring

tools/python_reference/sero_crypto.py   interop reference/test harness
```

## Container format (`ENCv1`)

```
[0:5)     "ENCv1"                        5 bytes   magic / version
[5:9)     encrypted_key_len (uint32 BE)  4 bytes
[9:9+N)   RSA-OAEP-SHA256(AES-256 key)   N bytes   (N ≈ 256 for a 2048-bit RSA key)
[..+12)   AES-GCM IV                     12 bytes  fresh random per file/message
[..EOF)   AES-256-GCM ciphertext || 16-byte GCM tag
```

The GCM tag is *not* framed separately - both `javax.crypto.Cipher` (Android)
and CommonCrypto's incremental GCM (iOS) append the 16-byte tag to the last
block of output, exactly like PyCryptodome/`cryptography` on the Python side
when the tag is concatenated after the ciphertext. This keeps all three
implementations byte-identical without extra framing.

Verified round-trip with `tools/python_reference/sero_crypto.py` (run it
directly: `pip install cryptography && python3 sero_crypto.py`).

## Streaming / memory

Both native engines use a fixed **8 MB** buffer
(`CryptoFormat.STREAM_BUFFER_SIZE` / `CryptoFormat.streamBufferSize`) and
`FileInputStream`/`FileOutputStream` + `Cipher.update()`/`doFinal()` on
Android, `InputStream`/`OutputStream` + incremental GCM calls on iOS. Memory
usage is therefore constant regardless of file size - the design was
validated conceptually against 20GB+ files; actual throughput is bound by
device storage I/O, not RAM.

## Key management

- **Android**: keys generated on-device live in the Android Keystore
  (hardware/TEE-backed, non-exportable private key). Keys imported from an
  external source (e.g. a keypair from the Python tool) are stored as PKCS8
  bytes encrypted at rest by a Keystore-resident AES-256-GCM wrapping key -
  see `SecureKeyStore.kt` for the full rationale. **`minSdk` is pinned to
  30** so `KeyGenParameterSpec.setMgf1Digests(SHA-256)` is available,
  which is required for Keystore-generated keys to produce OAEP ciphertext
  using MGF1-SHA256 (otherwise Android defaults to MGF1-SHA1 and the output
  would not match Python/iOS).
- **iOS**: both generated and imported keys are stored as genuine Keychain
  `SecKey` items (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, not
  iCloud-synced). `DER.swift` converts between the PKCS#1 wire format
  `SecKey` uses internally and the standard SPKI (public) / PKCS8 (private)
  DER encodings Android and Python use, so exported keys are drop-in
  compatible across all three.

## ⚠️ iOS: CommonCrypto GCM streaming caveat (please read)

There is no fully **public** Apple API for incremental (chunk-by-chunk),
single-tag AES-GCM on iOS. `CryptoKit`'s `AES.GCM` is one-shot only
(everything in memory at once), which would violate the "no full file in
memory" requirement for large files. The actual incremental primitives
(`CCCryptorGCMSetIV`, `CCCryptorGCMEncrypt/Decrypt`, `CCCryptorGCMFinalize`)
ship inside every iOS build's CommonCrypto library and are what this project
uses (see `CommonCryptoGCM.h` + `StreamingAESGCM.swift`), but they are only
declared in Apple's *private/SPI* header, not the public umbrella header -
some third-party SDKs using the older sibling symbols have been flagged by
App Store static analysis in the past (see the code comments in
`StreamingAESGCM.swift` for a citation). **Before shipping to the App
Store**, validate with a TestFlight build. If Apple's review tooling ever
flags these symbols, the documented fallback is to switch to a chunked
`CryptoKit.AES.GCM` scheme with a custom multi-tag container format (a
larger change, since it's no longer byte-compatible with a single-tag
Python/Android file without also updating the Python side to chunk the
same way).

## Dart API

```dart
final crypto = SeroCrypto();

await crypto.generateRSAKeyPair('me');
await crypto.importPublicKey('bob', bobPublicKeyDer);

final job = crypto.encryptFile(
  inputPath: '/path/in.bin',
  outputPath: '/path/out.encv1',
  publicKeyAlias: 'bob',
);
job.progress.listen((p) => print(p.fraction));
final ok = await job.result;      // or: await job.cancel();

await crypto.decryptFile(
  inputPath: '/path/out.encv1',
  outputPath: '/path/restored.bin',
  privateKeyAlias: 'me',
).result;

final cipher = await crypto.encryptBytes(someBytes, 'bob');
final plain = await crypto.decryptBytes(cipher, 'me');
```

All calls are `async`/return `Future`s (or a `CryptoJob` whose `result` is a
`Future<bool>`, so streaming calls remain cancellable/observable while still
being fully awaitable).

## Error handling

Every native failure surfaces in Dart as a `CryptoException` with a stable
`CryptoErrorCode` (`invalidFormat`, `keyNotFound`, `authenticationFailed`,
`cancelled`, etc.) - see `crypto_exception.dart`. `authenticationFailed`
means the GCM tag didn't verify (wrong key or corrupted/tampered data).

## Thread safety

- Android: every call runs on a dedicated `ExecutorService` (cached thread
  pool); results are always posted back on the main thread as the Flutter
  engine requires. `EncryptionEngine` holds no mutable shared state across
  calls.
- iOS: every call runs on a concurrent `DispatchQueue`; results are posted
  back via `DispatchQueue.main`. `CancellationToken` uses an `NSLock`.

## What to test after unzipping

1. `flutter pub get`
2. Android: open in Android Studio, let Gradle sync (minSdk 30 now
   required - bump your test devices/emulators accordingly), run on a
   device/emulator.
3. iOS: `cd ios && pod install` if you use CocoaPods for other plugins
   (this engine adds no pod dependencies itself), open
   `Runner.xcworkspace` in Xcode, build. The `Crypto` group has already been
   added to the `Runner` target's Sources build phase and the bridging
   header in `project.pbxproj`/`Runner-Bridging-Header.h` - if Xcode
   complains about missing file references, right-click the `Crypto` group
   → "Add Files to Runner..." and re-select the folder to resync.
4. Round-trip a file end-to-end (encrypt then decrypt) and diff it against
   the original.
5. Cross-check with `tools/python_reference/sero_crypto.py`: encrypt in
   Flutter, decrypt in Python (and vice versa) using exported/imported keys.
