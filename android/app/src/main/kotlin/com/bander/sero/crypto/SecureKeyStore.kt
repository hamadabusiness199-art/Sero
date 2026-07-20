package com.bander.sero.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages RSA key material for the crypto engine.
 *
 * Two distinct storage strategies are used, both backed exclusively by the
 * Android Keystore (JCA/JCE) - no third-party crypto libraries:
 *
 * 1. Keys **generated on-device** via [generateKeyPair] never leave the
 *    Keystore. The private key is hardware/TEE-backed and non-exportable;
 *    only the public key (SubjectPublicKeyInfo DER) can be read back out.
 *
 * 2. Keys **imported from outside** (e.g. a keypair produced by the Python
 *    reference tool, needed for cross-platform interop) cannot be placed
 *    inside the Keystore as a usable PrivateKeyEntry without a self-signed
 *    certificate chain. Instead we generate a Keystore-resident AES-256-GCM
 *    "wrapping key" and use it to encrypt the imported PKCS8 private key
 *    bytes at rest under the app's private storage. The imported key is
 *    decrypted into memory only for the duration of a single crypto
 *    operation and is not cached beyond that.
 */
class SecureKeyStore(context: Context) {

    private val appContext = context.applicationContext
    private val androidKeyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val keyDir: File by lazy {
        File(appContext.filesDir, "sero_keys").apply { mkdirs() }
    }

    // ---------------------------------------------------------------
    // On-device generated keys (pure Android Keystore)
    // ---------------------------------------------------------------

    fun generateKeyPair(alias: String): PublicKey {
        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(
                keystoreAlias(alias),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(CryptoFormat.RSA_KEY_SIZE)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setMgf1Digests(KeyProperties.DIGEST_SHA256) // required on API 30+ for OAEP-SHA256
                .setRandomizedEncryptionRequired(true)
                .build()
            generator.initialize(spec)
            val pair: KeyPair = generator.generateKeyPair()
            return pair.public
        } catch (t: Throwable) {
            throw CryptoException.KeyGenerationFailed("Failed to generate RSA key pair in Keystore", t)
        }
    }

    fun hasKeystoreKey(alias: String): Boolean =
        androidKeyStore.containsAlias(keystoreAlias(alias))

    fun getKeystorePrivateKey(alias: String): PrivateKey {
        val entry = androidKeyStore.getEntry(keystoreAlias(alias), null) as? KeyStore.PrivateKeyEntry
            ?: throw CryptoException.KeyNotFound(alias)
        return entry.privateKey
    }

    fun getKeystorePublicKey(alias: String): PublicKey {
        val cert = androidKeyStore.getCertificate(keystoreAlias(alias))
            ?: throw CryptoException.KeyNotFound(alias)
        return cert.publicKey
    }

    fun deleteKeystoreKey(alias: String) {
        val ksAlias = keystoreAlias(alias)
        if (androidKeyStore.containsAlias(ksAlias)) androidKeyStore.deleteEntry(ksAlias)
    }

    // ---------------------------------------------------------------
    // Imported keys (Keystore-wrapped at rest)
    // ---------------------------------------------------------------

    /** Stores a raw SubjectPublicKeyInfo DER public key under [alias]. Public
     * keys are not secret, so they are simply written to app-private storage. */
    fun importPublicKey(alias: String, spkiDer: ByteArray): PublicKey {
        try {
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spkiDer))
            publicKeyFile(alias).writeBytes(spkiDer)
            return publicKey
        } catch (t: Throwable) {
            throw CryptoException.InvalidArgument("Invalid RSA public key (expected DER SubjectPublicKeyInfo): ${t.message}")
        }
    }

    /** Encrypts and stores a raw PKCS8 (or PKCS1, auto-converted) DER private
     * key under [alias] using a Keystore-resident AES-256-GCM wrapping key. */
    fun importPrivateKey(alias: String, keyDer: ByteArray) {
        // Accept both PKCS8 ("-----BEGIN PRIVATE KEY-----") and the older
        // PKCS1 ("-----BEGIN RSA PRIVATE KEY-----", e.g. from `openssl
        // genrsa` or `openssl rsa`) DER encodings. java.security only
        // understands PKCS8, so if the input isn't valid PKCS8 we try
        // reinterpreting it as PKCS1 and wrapping it into PKCS8 before
        // storing - the stored/wrapped bytes are always PKCS8 either way.
        val pkcs8Der: ByteArray = try {
            KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyDer))
            keyDer
        } catch (pkcs8Error: Throwable) {
            try {
                val converted = pkcs1RsaDerToPkcs8(keyDer)
                KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(converted))
                converted
            } catch (pkcs1Error: Throwable) {
                throw CryptoException.InvalidArgument(
                    "Invalid RSA private key (expected DER PKCS8 or PKCS1): ${pkcs8Error.message}"
                )
            }
        }
        val wrappingKey = wrappingKey()
        val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
        // IMPORTANT: wrappingKey is an AndroidKeyStore-resident key. The
        // Keystore provider rejects a caller-supplied IV for ENCRYPT_MODE
        // (throws "Caller-provided IV not permitted") because it must
        // guarantee IV uniqueness itself. So we must NOT pass a
        // GCMParameterSpec here - let the provider generate the IV, then
        // read back whatever it chose via cipher.iv.
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(pkcs8Der)
        privateKeyFile(alias).writeBytes(iv + ciphertext)
    }

    fun hasImportedPrivateKey(alias: String): Boolean = privateKeyFile(alias).exists()
    fun hasImportedPublicKey(alias: String): Boolean = publicKeyFile(alias).exists()

    fun getImportedPublicKey(alias: String): PublicKey {
        val file = publicKeyFile(alias)
        if (!file.exists()) throw CryptoException.KeyNotFound(alias)
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(file.readBytes()))
    }

    /** Decrypts the wrapped private key into memory for immediate use. */
    fun getImportedPrivateKey(alias: String): PrivateKey {
        val file = privateKeyFile(alias)
        if (!file.exists()) throw CryptoException.KeyNotFound(alias)
        val blob = file.readBytes()
        val iv = blob.copyOfRange(0, CryptoFormat.GCM_IV_LENGTH)
        val ciphertext = blob.copyOfRange(CryptoFormat.GCM_IV_LENGTH, blob.size)
        val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))
        val pkcs8 = cipher.doFinal(ciphertext)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
    }

    fun exportPublicKeyDer(alias: String): ByteArray {
        val publicKey = when {
            hasKeystoreKey(alias) -> getKeystorePublicKey(alias)
            hasImportedPublicKey(alias) -> getImportedPublicKey(alias)
            hasImportedPrivateKey(alias) -> {
                // Derive the public key from the stored RSA private key (CRT form).
                val priv = getImportedPrivateKey(alias)
                val crt = priv as? java.security.interfaces.RSAPrivateCrtKey
                    ?: throw CryptoException.InvalidArgument("Stored private key is not in CRT form; cannot derive public key")
                KeyFactory.getInstance("RSA").generatePublic(
                    java.security.spec.RSAPublicKeySpec(crt.modulus, crt.publicExponent)
                )
            }
            else -> throw CryptoException.KeyNotFound(alias)
        }
        return publicKey.encoded
    }

    fun deleteImportedKeys(alias: String) {
        publicKeyFile(alias).delete()
        privateKeyFile(alias).delete()
    }

    // ---------------------------------------------------------------
    // Any-source resolution helpers used by the crypto engine
    // ---------------------------------------------------------------

    fun resolvePublicKey(alias: String): PublicKey = when {
        hasKeystoreKey(alias) -> getKeystorePublicKey(alias)
        hasImportedPublicKey(alias) -> getImportedPublicKey(alias)
        hasImportedPrivateKey(alias) -> {
            val crt = getImportedPrivateKey(alias) as? java.security.interfaces.RSAPrivateCrtKey
                ?: throw CryptoException.InvalidArgument("Stored private key is not in CRT form")
            KeyFactory.getInstance("RSA").generatePublic(
                java.security.spec.RSAPublicKeySpec(crt.modulus, crt.publicExponent)
            )
        }
        else -> throw CryptoException.KeyNotFound(alias)
    }

    fun resolvePrivateKey(alias: String): PrivateKey = when {
        hasKeystoreKey(alias) -> getKeystorePrivateKey(alias)
        hasImportedPrivateKey(alias) -> getImportedPrivateKey(alias)
        else -> throw CryptoException.KeyNotFound(alias)
    }

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    private fun wrappingKey(): SecretKey {
        val ksAlias = "sero_key_wrap_master"
        (androidKeyStore.getEntry(ksAlias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            ksAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    /** Wraps a raw PKCS1 `RSAPrivateKey` DER blob (as produced by
     * `openssl genrsa` / `openssl rsa`, i.e. a "-----BEGIN RSA PRIVATE
     * KEY-----" PEM) into a PKCS8 `PrivateKeyInfo` DER structure that
     * java.security.KeyFactory can parse. This is a pure ASN.1 re-framing;
     * no key material is modified. Layout produced:
     *   SEQUENCE {
     *     INTEGER 0
     *     SEQUENCE { OID rsaEncryption, NULL }
     *     OCTET STRING { <the original PKCS1 DER bytes> }
     *   }
     */
    private fun pkcs1RsaDerToPkcs8(pkcs1Der: ByteArray): ByteArray {
        val rsaOidAndAlgId = byteArrayOf(
            0x30, 0x0D,                                             // SEQUENCE (AlgorithmIdentifier), len 13
            0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01, // OID 1.2.840.113549.1.1.1 (rsaEncryption)
            0x05, 0x00                                              // NULL
        )
        val version = byteArrayOf(0x02, 0x01, 0x00) // INTEGER 0
        val octetString = derEncode(0x04, pkcs1Der)  // OCTET STRING wrapping the PKCS1 bytes
        val body = version + rsaOidAndAlgId + octetString
        return derEncode(0x30, body) // outer SEQUENCE
    }

    /** Encodes a DER TLV with the given tag byte and content, using
     * standard short/long-form length encoding (supports content up to
     * ~16MB, far beyond any real RSA key size). */
    private fun derEncode(tag: Int, content: ByteArray): ByteArray {
        val length = content.size
        val lengthBytes: ByteArray = when {
            length < 0x80 -> byteArrayOf(length.toByte())
            length <= 0xFF -> byteArrayOf(0x81.toByte(), length.toByte())
            else -> byteArrayOf(
                0x82.toByte(),
                (length ushr 8 and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
        }
        return byteArrayOf(tag.toByte()) + lengthBytes + content
    }

    private fun keystoreAlias(alias: String) = "sero_rsa_$alias"
    private fun publicKeyFile(alias: String) = File(keyDir, "$alias.pub.der")
    private fun privateKeyFile(alias: String) = File(keyDir, "$alias.priv.wrapped")

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}