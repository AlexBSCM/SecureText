package com.securetext.app.crypto.keywrap

import com.securetext.app.crypto.CryptoRandom
import com.securetext.app.crypto.Stx2Constants
import com.securetext.app.crypto.argon2.Argon2id
import com.securetext.app.crypto.primitives.ChaCha20Poly1305Ietf
import org.bouncycastle.crypto.InvalidCipherTextException

class KeyVaultException(message: String, cause: Throwable? = null) : Exception(message, cause)

class WrongPasswordException : Exception("Wrong password")

data class SealedBlob(val nonce: ByteArray, val ciphertext: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SealedBlob) return false
        return nonce.contentEquals(other.nonce) && ciphertext.contentEquals(other.ciphertext)
    }
    override fun hashCode(): Int = nonce.contentHashCode() * 31 + ciphertext.contentHashCode()
}

object KeyVaultCrypto {
    const val KEY_AAD = "SecureText private key v2"
    const val KEK_CHECK_AAD = "SecureText KEK check v2"
    const val SALT_BYTES = 16
    const val NONCE_BYTES = ChaCha20Poly1305Ietf.NONCE_BYTES
    const val KEK_BYTES = 32
    private val KEK_CHECK_MAGIC = "secure-text-kek-check-v2".toByteArray(Charsets.UTF_8)

    fun deriveKek(password: ByteArray, salt: ByteArray): ByteArray {
        require(salt.size == SALT_BYTES) { "Salt must be $SALT_BYTES bytes" }
        return Argon2id.deriveKey(
            password, salt,
            Stx2Constants.ARGON2_TIME_COST,
            Stx2Constants.ARGON2_MEMORY_KIB,
            Stx2Constants.ARGON2_PARALLELISM,
            Stx2Constants.ARGON2_HASH_LEN
        )
    }

    fun seal(kek: ByteArray, plaintext: ByteArray, aad: ByteArray = KEY_AAD.toByteArray(Charsets.UTF_8)): SealedBlob {
        val nonce = CryptoRandom.bytes(NONCE_BYTES)
        val ct = ChaCha20Poly1305Ietf.encrypt(kek, nonce, plaintext, aad)
        return SealedBlob(nonce, ct)
    }

    fun open(kek: ByteArray, blob: SealedBlob, aad: ByteArray = KEY_AAD.toByteArray(Charsets.UTF_8)): ByteArray {
        return try {
            ChaCha20Poly1305Ietf.decrypt(kek, blob.nonce, blob.ciphertext, aad)
        } catch (e: InvalidCipherTextException) {
            throw KeyVaultException("AEAD open failed: wrong key or corrupted data", e)
        } catch (e: Exception) {
            throw KeyVaultException("AEAD open failed: ${e.message}", e)
        }
    }

    fun makeKekCheck(kek: ByteArray): SealedBlob =
        seal(kek, KEK_CHECK_MAGIC, KEK_CHECK_AAD.toByteArray(Charsets.UTF_8))

    fun verifyKekCheck(kek: ByteArray, blob: SealedBlob): Boolean {
        return try {
            val magic = open(kek, blob, KEK_CHECK_AAD.toByteArray(Charsets.UTF_8))
            magic.contentEquals(KEK_CHECK_MAGIC)
        } catch (_: KeyVaultException) {
            false
        }
    }
}
