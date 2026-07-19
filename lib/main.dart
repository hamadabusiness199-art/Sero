import 'dart:async';
import 'dart:io';

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
      title: 'Sero - Native Crypto Test',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const DecryptTestScreen(),
    );
  }
}

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
  double? _progressFraction;
  bool _isBusy = false;
  CryptoJob? _activeJob;
  final List<String> _log = [];

  void _addLog(String message) {
    final time = TimeOfDay.now().format(context);
    setState(() => _log.insert(0, '[$time] $message'));
  }

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
      return;
    }

    setState(() {
      _isBusy = true;
      _progressFraction = 0;
    });

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
      await progressSub.cancel();
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
      appBar: AppBar(title: const Text('Sero — اختبار محرك التشفير الأصلي')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
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
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _isBusy ? null : _importPrivateKey,
                    icon: const Icon(Icons.file_upload),
                    label: const Text('استيراد مفتاح خاص'),
                  ),
                ),
              ],
            ),
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
}
