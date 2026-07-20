import 'dart:async';
<<<<<<< HEAD
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
=======
import 'dart:io';
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import 'crypto/crypto.dart';

void main() {
  runApp(const SeroTestApp());
}

class SeroTestApp extends StatelessWidget {
  const SeroTestApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
<<<<<<< HEAD
      title: 'Sero - Native Crypto',
=======
      title: 'Sero - Native Crypto Test',
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
<<<<<<< HEAD
      home: const SeroHomeScreen(),
=======
      home: const DecryptTestScreen(),
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
    );
  }
}

<<<<<<< HEAD
enum _Mode { encrypt, decrypt }

/// شاشة واحدة بسيطة: اختيار مستند + اختيار مفتاح، وزرارين "تشفير" و
/// "فك تشفير". بتستخدم نفس محرك SeroCrypto (Kotlin/Swift) اللي بيكتب ويقرأ
/// نفس تنسيق ENCv1 المتوافق مع سكربتات Python المرجعية (encrypt_file /
/// decrypt_file: RSA-OAEP-SHA256 لتغليف مفتاح AES-256-GCM).
class SeroHomeScreen extends StatefulWidget {
  const SeroHomeScreen({super.key});

  @override
  State<SeroHomeScreen> createState() => _SeroHomeScreenState();
}

class _SeroHomeScreenState extends State<SeroHomeScreen> {
  final SeroCrypto _crypto = SeroCrypto();

  // alias داخلي ثابت - المفتاح بيتستورد من جديد قبل كل عملية من الملف
  // اللي المستخدم اختاره، فمفيش داعي المستخدم يكتب اسم يدويًا.
  static const _keyAlias = 'sero_session_key';

  String? _documentPath;
  String? _keyPath;
=======
/// Minimal screen to exercise the native SeroCrypto engine end-to-end:
/// generate/import a private key, pick an encrypted (ENCv1) file, decrypt
/// it, and watch native progress + errors live.
class DecryptTestScreen extends StatefulWidget {
  const DecryptTestScreen({super.key});

  @override
  State<DecryptTestScreen> createState() => _DecryptTestScreenState();
}

class _DecryptTestScreenState extends State<DecryptTestScreen> {
  final SeroCrypto _crypto = SeroCrypto();
  final TextEditingController _aliasController =
      TextEditingController(text: 'test-key');

  String? _encryptedFilePath;
  String? _outputFilePath;
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
  double? _progressFraction;
  bool _isBusy = false;
  CryptoJob? _activeJob;
  final List<String> _log = [];

  void _addLog(String message) {
    final time = TimeOfDay.now().format(context);
    setState(() => _log.insert(0, '[$time] $message'));
  }

<<<<<<< HEAD
  String _basename(String path) => path.split(Platform.pathSeparator).last;

  /// المفاتيح المرجعية (Python `serialization.load_pem_*_key`) بتتخزن
  /// كـ PEM نصي. الـ native جوانا بيتوقع DER خام (PKCS8 للخاص / SPKI
  /// للعام)، فبنشيل الـ PEM headers ونفك الـ base64 هنا لو الملف PEM؛
  /// لو أصلاً DER (binary) بنبعته زي ما هو.
  Uint8List _pemOrDerToDer(Uint8List bytes) {
    final text = String.fromCharCodes(bytes.where((b) => b < 128));
    if (text.contains('-----BEGIN')) {
      final b64 = text
          .split('\n')
          .where((line) => line.isNotEmpty && !line.startsWith('-----'))
          .join();
      return base64Decode(b64.trim());
    }
    return bytes;
  }

  Future<void> _pickDocument() async {
    final result = await FilePicker.pickFiles(
      dialogTitle: 'اختر الملف (مستند / صورة / فيديو / .enc)',
      type: FileType.any,
    );
    if (result == null || result.files.single.path == null) return;
    setState(() => _documentPath = result.files.single.path);
    _addLog('📄 تم اختيار الملف: ${_basename(_documentPath!)}');
  }

  Future<void> _pickKey() async {
    final result = await FilePicker.pickFiles(
      dialogTitle: 'اختر المفتاح (public.pem أو private.pem)',
      type: FileType.any,
    );
    if (result == null || result.files.single.path == null) return;
    setState(() => _keyPath = result.files.single.path);
    _addLog('🔑 تم اختيار المفتاح: ${_basename(_keyPath!)}');
  }

  Future<void> _run(_Mode mode) async {
    final docPath = _documentPath;
    final keyPath = _keyPath;
    if (docPath == null) {
      _addLog('⚠️ اختر الملف الأول');
      return;
    }
    if (keyPath == null) {
      _addLog('⚠️ اختر المفتاح الأول');
=======
  Future<void> _generateKey() async {
    final alias = _aliasController.text.trim();
    if (alias.isEmpty) {
      _addLog('⚠️ اكتب اسم (alias) للمفتاح الأول');
      return;
    }
    setState(() => _isBusy = true);
    try {
      final pub = await _crypto.generateRSAKeyPair(alias);
      _addLog('✅ تم توليد مفتاح RSA جديد "$alias" (public key: ${pub.length} byte)');
    } catch (e) {
      _addLog('❌ فشل توليد المفتاح: $e');
    } finally {
      setState(() => _isBusy = false);
    }
  }

  Future<void> _importPrivateKey() async {
    final alias = _aliasController.text.trim();
    if (alias.isEmpty) {
      _addLog('⚠️ اكتب اسم (alias) للمفتاح الأول');
      return;
    }
    final result = await FilePicker.pickFiles(
      dialogTitle: 'اختر ملف المفتاح الخاص (PKCS8 DER, .der/.pem)',
      type: FileType.any,
    );
    if (result == null || result.files.single.path == null) return;

    setState(() => _isBusy = true);
    try {
      final bytes = await File(result.files.single.path!).readAsBytes();
      await _crypto.importPrivateKey(alias, bytes);
      _addLog('✅ تم استيراد المفتاح الخاص تحت الاسم "$alias"');
    } catch (e) {
      _addLog('❌ فشل استيراد المفتاح: $e');
    } finally {
      setState(() => _isBusy = false);
    }
  }

  Future<void> _pickEncryptedFile() async {
    final result = await FilePicker.pickFiles(
      dialogTitle: 'اختر ملف مشفّر (ENCv1)',
      type: FileType.any,
    );
    if (result == null || result.files.single.path == null) return;

    final inputPath = result.files.single.path!;
    setState(() {
      _encryptedFilePath = inputPath;
      _outputFilePath = '$inputPath.dec';
    });
    _addLog('📄 تم اختيار: $inputPath');
  }

  Future<void> _decrypt() async {
    final alias = _aliasController.text.trim();
    final inputPath = _encryptedFilePath;
    final outputPath = _outputFilePath;

    if (alias.isEmpty) {
      _addLog('⚠️ اكتب اسم (alias) للمفتاح الأول');
      return;
    }
    if (inputPath == null || outputPath == null) {
      _addLog('⚠️ اختر ملف مشفّر الأول');
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
      return;
    }

    setState(() {
      _isBusy = true;
      _progressFraction = 0;
    });

<<<<<<< HEAD
    try {
      final keyBytes = _pemOrDerToDer(await File(keyPath).readAsBytes());

      final CryptoJob job;
      final String outputPath;

      if (mode == _Mode.encrypt) {
        outputPath = '$docPath.enc';
        _addLog('🔑 استيراد المفتاح العام...');
        await _crypto.importPublicKey(_keyAlias, keyBytes);
        _addLog('▶️ بدء التشفير...');
        job = _crypto.encryptFile(
          inputPath: docPath,
          outputPath: outputPath,
          publicKeyAlias: _keyAlias,
        );
      } else {
        outputPath = docPath.endsWith('.enc')
            ? docPath.substring(0, docPath.length - 4)
            : '$docPath.dec';
        _addLog('🔑 استيراد المفتاح الخاص...');
        await _crypto.importPrivateKey(_keyAlias, keyBytes);
        _addLog('▶️ بدء فك التشفير...');
        job = _crypto.decryptFile(
          inputPath: docPath,
          outputPath: outputPath,
          privateKeyAlias: _keyAlias,
        );
      }

      _activeJob = job;
      final progressSub = job.progress.listen((p) {
        setState(() => _progressFraction = p.fraction);
      });

      try {
        final success = await job.result;
        final label = mode == _Mode.encrypt ? 'التشفير' : 'فك التشفير';
        _addLog(success
            ? '✅ تم $label بنجاح -> $outputPath'
            : '❌ فشل $label (رجع false من الجهة الأصلية)');
      } finally {
        await progressSub.cancel();
      }
=======
    _addLog('▶️ بدء فك التشفير...');
    final job = _crypto.decryptFile(
      inputPath: inputPath,
      outputPath: outputPath,
      privateKeyAlias: alias,
    );
    _activeJob = job;

    final progressSub = job.progress.listen((p) {
      setState(() => _progressFraction = p.fraction);
    });

    try {
      final success = await job.result;
      _addLog(success
          ? '✅ تم فك التشفير بنجاح -> $outputPath'
          : '❌ فشل فك التشفير (رجع false من الجهة الأصلية)');
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
    } on CryptoException catch (e) {
      if (e.isAuthenticationFailure) {
        _addLog('❌ فشل التحقق (Auth) - غالبًا المفتاح غلط أو الملف اتغير');
      } else if (e.isCancelled) {
        _addLog('⏹️ تم إلغاء العملية');
      } else {
        _addLog('❌ خطأ (${e.code.name}): ${e.message}');
      }
    } catch (e) {
      _addLog('❌ خطأ غير متوقع: $e');
    } finally {
<<<<<<< HEAD
=======
      await progressSub.cancel();
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
      setState(() {
        _isBusy = false;
        _activeJob = null;
        _progressFraction = null;
      });
    }
  }

  Future<void> _cancelJob() async {
    await _activeJob?.cancel();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
<<<<<<< HEAD
      appBar: AppBar(title: const Text('Sero — تشفير / فك تشفير')),
=======
      appBar: AppBar(title: const Text('Sero — اختبار محرك التشفير الأصلي')),
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
<<<<<<< HEAD
            OutlinedButton.icon(
              onPressed: _isBusy ? null : _pickDocument,
              icon: const Icon(Icons.folder_open),
              label: Text(_documentPath == null
                  ? 'اختيار الملف'
                  : 'الملف: ${_basename(_documentPath!)}'),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _isBusy ? null : _pickKey,
              icon: const Icon(Icons.vpn_key),
              label: Text(_keyPath == null
                  ? 'اختيار المفتاح'
                  : 'المفتاح: ${_basename(_keyPath!)}'),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: (_isBusy || _documentPath == null || _keyPath == null)
                        ? null
                        : () => _run(_Mode.encrypt),
                    icon: const Icon(Icons.lock),
                    label: const Text('تشفير'),
=======
            TextField(
              controller: _aliasController,
              decoration: const InputDecoration(
                labelText: 'اسم المفتاح (alias)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _isBusy ? null : _generateKey,
                    icon: const Icon(Icons.vpn_key),
                    label: const Text('توليد مفتاح جديد'),
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
<<<<<<< HEAD
                  child: FilledButton.tonalIcon(
                    onPressed: (_isBusy || _documentPath == null || _keyPath == null)
                        ? null
                        : () => _run(_Mode.decrypt),
                    icon: const Icon(Icons.lock_open),
                    label: const Text('فك التشفير'),
=======
                  child: OutlinedButton.icon(
                    onPressed: _isBusy ? null : _importPrivateKey,
                    icon: const Icon(Icons.file_upload),
                    label: const Text('استيراد مفتاح خاص'),
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
                  ),
                ),
              ],
            ),
<<<<<<< HEAD
=======
            const SizedBox(height: 20),
            OutlinedButton.icon(
              onPressed: _isBusy ? null : _pickEncryptedFile,
              icon: const Icon(Icons.folder_open),
              label: Text(_encryptedFilePath == null
                  ? 'اختيار ملف مشفّر (ENCv1)'
                  : 'الملف: ${_encryptedFilePath!.split(Platform.pathSeparator).last}'),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: (_isBusy || _encryptedFilePath == null) ? null : _decrypt,
              icon: const Icon(Icons.lock_open),
              label: const Text('فك التشفير الآن (Native)'),
            ),
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
            if (_isBusy) ...[
              const SizedBox(height: 12),
              LinearProgressIndicator(value: _progressFraction),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: _cancelJob,
                  child: const Text('إلغاء'),
                ),
              ),
            ],
            const SizedBox(height: 16),
            const Divider(),
            const Align(
              alignment: Alignment.centerRight,
              child: Text('السجل (Log)', style: TextStyle(fontWeight: FontWeight.bold)),
            ),
            Expanded(
              child: ListView.builder(
                itemCount: _log.length,
                itemBuilder: (context, i) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Text(_log[i], style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
<<<<<<< HEAD
}
=======
}
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
