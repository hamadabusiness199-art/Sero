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

    /** Encrypts and stores a raw PKCS8 DER private key under [alias] using a
     * Keystore-resident AES-256-GCM wrapping key. */
    fun importPrivateKey(alias: String, pkcs8Der: ByteArray) {
        try {
            // Validate it actually parses as an RSA private key before storing.
            KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8Der))
        } catch (t: Throwable) {
            throw CryptoException.InvalidArgument("Invalid RSA private key (expected DER PKCS8): ${t.message}")
        }
        val wrappingKey = wrappingKey()
        val cipher = Cipher.getInstance(CryptoFormat.AES_TRANSFORMATION)
        val iv = ByteArray(CryptoFormat.GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey, GCMParameterSpec(CryptoFormat.GCM_TAG_LENGTH_BITS, iv))
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

    private fun keystoreAlias(alias: String) = "sero_rsa_$alias"
    private fun publicKeyFile(alias: String) = File(keyDir, "$alias.pub.der")
    private fun privateKeyFile(alias: String) = File(keyDir, "$alias.priv.wrapped")

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
