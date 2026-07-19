package com.bander.sero.crypto

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Registers the native crypto engine with Flutter.
 *
 * - `sero/crypto/methods`  (MethodChannel) - request/response calls
 * - `sero/crypto/progress` (EventChannel)  - `{jobId, bytesProcessed, totalBytes}` progress ticks
 *
 * Every call is dispatched to a dedicated background executor so the
 * platform (UI) thread is never blocked by IO or crypto work. Results are
 * always posted back on the main thread, as required by the Flutter engine.
 * The engine itself ([EncryptionEngine]) does not hold any shared mutable
 * state across calls, so concurrent operations on different aliases/jobs
 * are safe; per-job cancellation tokens prevent cross-talk between jobs.
 */
class CryptoPlugin : FlutterPlugin {

    private lateinit var methodChannel: MethodChannel
    private lateinit var progressChannel: EventChannel
    private lateinit var engine: EncryptionEngine
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val activeJobs = ConcurrentHashMap<String, CancellationToken>()
    private var progressSink: EventChannel.EventSink? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        engine = EncryptionEngine(binding.applicationContext)

        methodChannel = MethodChannel(binding.binaryMessenger, METHOD_CHANNEL)
        methodChannel.setMethodCallHandler { call, result -> handle(call, result) }

        progressChannel = EventChannel(binding.binaryMessenger, PROGRESS_CHANNEL)
        progressChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                progressSink = events
            }
            override fun onCancel(arguments: Any?) {
                progressSink = null
            }
        })
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        progressChannel.setStreamHandler(null)
        activeJobs.values.forEach { it.cancel() }
        executor.shutdown()
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateRSAKeyPair" -> runAsync(result) {
                val alias = call.requireString("alias")
                mapOf("publicKeyDer" to engine.generateRSAKeyPair(alias).b64())
            }
            "importPublicKey" -> runAsync(result) {
                val alias = call.requireString("alias")
                val der = call.requireBytes("publicKeyDer")
                engine.importPublicKey(alias, der)
                mapOf("success" to true)
            }
            "importPrivateKey" -> runAsync(result) {
                val alias = call.requireString("alias")
                val der = call.requireBytes("privateKeyDer")
                engine.importPrivateKey(alias, der)
                mapOf("success" to true)
            }
            "exportPublicKey" -> runAsync(result) {
                val alias = call.requireString("alias")
                mapOf("publicKeyDer" to engine.exportPublicKey(alias).b64())
            }
            "deleteKey" -> runAsync(result) {
                engine.deleteKey(call.requireString("alias"))
                mapOf("success" to true)
            }
            "encryptFile" -> runAsync(result) {
                val jobId = call.requireString("jobId")
                val token = registerJob(jobId)
                try {
                    engine.encryptFile(
                        inputPath = call.requireString("inputPath"),
                        outputPath = call.requireString("outputPath"),
                        publicKeyAlias = call.requireString("publicKeyAlias"),
                        token = token,
                        onProgress = { done, total -> emitProgress(jobId, done, total) }
                    )
                    mapOf("success" to true)
                } finally {
                    activeJobs.remove(jobId)
                }
            }
            "decryptFile" -> runAsync(result) {
                val jobId = call.requireString("jobId")
                val token = registerJob(jobId)
                try {
                    engine.decryptFile(
                        inputPath = call.requireString("inputPath"),
                        outputPath = call.requireString("outputPath"),
                        privateKeyAlias = call.requireString("privateKeyAlias"),
                        token = token,
                        onProgress = { done, total -> emitProgress(jobId, done, total) }
                    )
                    mapOf("success" to true)
                } finally {
                    activeJobs.remove(jobId)
                }
            }
            "encryptBytes" -> runAsync(result) {
                val data = call.requireBytes("data")
                val alias = call.requireString("publicKeyAlias")
                mapOf("data" to engine.encryptBytes(data, alias).b64())
            }
            "decryptBytes" -> runAsync(result) {
                val data = call.requireBytes("data")
                val alias = call.requireString("privateKeyAlias")
                mapOf("data" to engine.decryptBytes(data, alias).b64())
            }
            "cancelJob" -> {
                activeJobs[call.requireString("jobId")]?.cancel()
                result.success(mapOf("success" to true))
            }
            else -> result.notImplemented()
        }
    }

    private fun registerJob(jobId: String): CancellationToken {
        val token = CancellationToken()
        activeJobs[jobId] = token
        return token
    }

    private fun emitProgress(jobId: String, done: Long, total: Long) {
        mainHandler.post {
            progressSink?.success(mapOf("jobId" to jobId, "bytesProcessed" to done, "totalBytes" to total))
        }
    }

    /** Runs [block] on the background executor and marshals the outcome
     * (success map or typed error) back to Flutter on the main thread. */
    private fun runAsync(result: MethodChannel.Result, block: () -> Map<String, Any?>) {
        executor.execute {
            try {
                val value = block()
                mainHandler.post { result.success(value) }
            } catch (e: CryptoException) {
                mainHandler.post { result.error(e.code, e.message, null) }
            } catch (t: Throwable) {
                mainHandler.post { result.error("UNKNOWN_ERROR", t.message ?: t.toString(), null) }
            }
        }
    }

    private fun MethodCall.requireString(key: String): String =
        argument<String>(key) ?: throw CryptoException.InvalidArgument("Missing required argument '$key'")

    private fun MethodCall.requireBytes(key: String): ByteArray =
        argument<ByteArray>(key) ?: throw CryptoException.InvalidArgument("Missing required argument '$key'")

    private fun ByteArray.b64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

    companion object {
        private const val METHOD_CHANNEL = "sero/crypto/methods"
        private const val PROGRESS_CHANNEL = "sero/crypto/progress"
    }
}
