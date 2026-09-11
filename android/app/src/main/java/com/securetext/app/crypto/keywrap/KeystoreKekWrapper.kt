package com.securetext.app.crypto.keywrap

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

data class WrappedKek(val iv: ByteArray, val ciphertext: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WrappedKek) return false
        return iv.contentEquals(other.iv) && ciphertext.contentEquals(other.ciphertext)
    }
    override fun hashCode(): Int = iv.contentHashCode() * 31 + ciphertext.contentHashCode()
}

class KekWrapException(message: String, cause: Throwable? = null) : Exception(message, cause)

@Singleton
class KeystoreKekWrapper @Inject constructor() {
    fun wrapKekOrNull(kek: ByteArray): WrappedKek? {
        val key = try {
            ensureKey()
        } catch (_: Exception) {
            return null
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val ct = cipher.doFinal(kek)
            WrappedKek(cipher.iv, ct)
        } catch (_: Exception) {
            null
        }
    }

    fun prepareUnwrapCipher(iv: ByteArray): Cipher {
        val key = getExistingKey() ?: throw KekWrapException("Keystore wrap key missing")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KekWrapException("Wrap key invalidated by biometric enrollment", e)
        } catch (e: Exception) {
            throw KekWrapException("Cannot init unwrap cipher: ${e.message}", e)
        }
        return cipher
    }

    fun unwrap(cipher: Cipher, ciphertext: ByteArray): ByteArray {
        return try {
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            throw KekWrapException("KEK unwrap failed: ${e.message}", e)
        }
    }

    fun removeKey() {
        val ks = keyStore()
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    private fun getExistingKey(): SecretKey? {
        val ks = keyStore()
        val entry = ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry ?: return null
        return entry.secretKey
    }

    private fun ensureKey(): SecretKey {
        getExistingKey()?.let { return it }
        return try {
            generateKey()
        } catch (e: Exception) {
            try {
                removeKey()
                generateKey()
            } catch (e2: Exception) {
                throw KekWrapException("Cannot create Keystore wrap key", e2)
            }
        }
    }

    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun keyStore(): KeyStore {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        return ks
    }

    companion object {
        const val ALIAS = "stx_kek_wrap"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }
}
