import Flutter
import Foundation

/// Registers the native crypto engine with Flutter, mirroring the Android
/// `CryptoPlugin.kt` channel names and payload shapes exactly.
///
/// - `sero/crypto/methods`  (FlutterMethodChannel) - request/response calls
/// - `sero/crypto/progress` (FlutterEventChannel)  - progress ticks
final class CryptoPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private let engine = CryptoEngine()
    private let queue = DispatchQueue(label: "sero.crypto.worker", qos: .userInitiated, attributes: .concurrent)
    private var activeJobs: [String: CancellationToken] = [:]
    private let jobsLock = NSLock()
    private var progressSink: FlutterEventSink?

    static func register(with registrar: FlutterPluginRegistrar) {
        let instance = CryptoPlugin()
        let methodChannel = FlutterMethodChannel(name: "sero/crypto/methods", binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(instance, channel: methodChannel)

        let progressChannel = FlutterEventChannel(name: "sero/crypto/progress", binaryMessenger: registrar.messenger())
        progressChannel.setStreamHandler(instance)
    }

    // MARK: FlutterStreamHandler (progress)

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        progressSink = events
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        progressSink = nil
        return nil
    }

    // MARK: FlutterMethodCallDelegate

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any] ?? [:]

        func run(_ block: @escaping () throws -> [String: Any]) {
            queue.async {
                do {
                    let value = try block()
                    DispatchQueue.main.async { result(value) }
                } catch let e as CryptoError {
                    DispatchQueue.main.async { result(FlutterError(code: e.code, message: e.message, details: nil)) }
                } catch {
                    DispatchQueue.main.async { result(FlutterError(code: "UNKNOWN_ERROR", message: error.localizedDescription, details: nil)) }
                }
            }
        }

        switch call.method {
        case "generateRSAKeyPair":
            run {
                let alias = try Self.requireString(args, "alias")
                let der = try self.engine.generateRSAKeyPair(alias: alias)
                return ["publicKeyDer": Self.base64(der)]
            }
        case "importPublicKey":
            run {
                let alias = try Self.requireString(args, "alias")
                let der = try Self.requireBytes(args, "publicKeyDer")
                try self.engine.importPublicKey(alias: alias, spkiDer: der)
                return ["success": true]
            }
        case "importPrivateKey":
            run {
                let alias = try Self.requireString(args, "alias")
                let der = try Self.requireBytes(args, "privateKeyDer")
                try self.engine.importPrivateKey(alias: alias, pkcs8Der: der)
                return ["success": true]
            }
        case "exportPublicKey":
            run {
                let alias = try Self.requireString(args, "alias")
                let der = try self.engine.exportPublicKey(alias: alias)
                return ["publicKeyDer": Self.base64(der)]
            }
        case "deleteKey":
            run {
                let alias = try Self.requireString(args, "alias")
                self.engine.deleteKey(alias: alias)
                return ["success": true]
            }
        case "encryptFile":
            run {
                let jobId = try Self.requireString(args, "jobId")
                let token = self.registerJob(jobId)
                defer { self.unregisterJob(jobId) }
                try self.engine.encryptFile(
                    inputPath: try Self.requireString(args, "inputPath"),
                    outputPath: try Self.requireString(args, "outputPath"),
                    publicKeyAlias: try Self.requireString(args, "publicKeyAlias"),
                    token: token,
                    onProgress: { done, total in self.emitProgress(jobId, done, total) }
                )
                return ["success": true]
            }
        case "decryptFile":
            run {
                let jobId = try Self.requireString(args, "jobId")
                let token = self.registerJob(jobId)
                defer { self.unregisterJob(jobId) }
                try self.engine.decryptFile(
                    inputPath: try Self.requireString(args, "inputPath"),
                    outputPath: try Self.requireString(args, "outputPath"),
                    privateKeyAlias: try Self.requireString(args, "privateKeyAlias"),
                    token: token,
                    onProgress: { done, total in self.emitProgress(jobId, done, total) }
                )
                return ["success": true]
            }
        case "encryptBytes":
            run {
                let data = try Self.requireBytes(args, "data")
                let alias = try Self.requireString(args, "publicKeyAlias")
                return ["data": Self.base64(try self.engine.encryptBytes(data, publicKeyAlias: alias))]
            }
        case "decryptBytes":
            run {
                let data = try Self.requireBytes(args, "data")
                let alias = try Self.requireString(args, "privateKeyAlias")
                return ["data": Self.base64(try self.engine.decryptBytes(data, privateKeyAlias: alias))]
            }
        case "cancelJob":
            if let jobId = args["jobId"] as? String {
                jobsLock.lock(); activeJobs[jobId]?.cancel(); jobsLock.unlock()
            }
            result(["success": true])
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: Job registry

    private func registerJob(_ jobId: String) -> CancellationToken {
        let token = CancellationToken()
        jobsLock.lock(); activeJobs[jobId] = token; jobsLock.unlock()
        return token
    }

    private func unregisterJob(_ jobId: String) {
        jobsLock.lock(); activeJobs.removeValue(forKey: jobId); jobsLock.unlock()
    }

    private func emitProgress(_ jobId: String, _ done: Int64, _ total: Int64) {
        DispatchQueue.main.async {
            self.progressSink?(["jobId": jobId, "bytesProcessed": done, "totalBytes": total])
        }
    }

    // MARK: Argument helpers

    private static func requireString(_ args: [String: Any], _ key: String) throws -> String {
        guard let value = args[key] as? String else {
            throw CryptoError.invalidArgument("Missing required argument '\(key)'")
        }
        return value
    }

    private static func requireBytes(_ args: [String: Any], _ key: String) throws -> [UInt8] {
        if let data = args[key] as? FlutterStandardTypedData { return [UInt8](data.data) }
        if let data = args[key] as? Data { return [UInt8](data) }
        throw CryptoError.invalidArgument("Missing required argument '\(key)'")
    }

    private static func base64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
    }
}
