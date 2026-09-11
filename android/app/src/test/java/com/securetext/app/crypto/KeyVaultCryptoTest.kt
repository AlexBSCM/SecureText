package com.securetext.app.crypto

import com.securetext.app.crypto.keywrap.KeyVaultCrypto
import com.securetext.app.crypto.keywrap.KeyVaultException
import com.securetext.app.crypto.keywrap.WrongPasswordException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyVaultCryptoTest {

    private val kek = CryptoRandom.bytes(32)
    private val data = "private-key-bytes".toByteArray(Charsets.UTF_8)

    @Test
    fun sealOpenRoundtrip() {
        val blob = KeyVaultCrypto.seal(kek, data)
        assertArrayEquals(data, KeyVaultCrypto.open(kek, blob))
        assertEquals(KeyVaultCrypto.NONCE_BYTES, blob.nonce.size)
        assertEquals(data.size + 16, blob.ciphertext.size)
    }

    @Test
    fun openWithWrongKeyFails() {
        val blob = KeyVaultCrypto.seal(kek, data)
        val wrongKey = CryptoRandom.bytes(32)
        try {
            KeyVaultCrypto.open(wrongKey, blob)
            throw AssertionError("Expected KeyVaultException")
        } catch (e: KeyVaultException) {
        }
    }

    @Test
    fun tamperedCiphertextFails() {
        val blob = KeyVaultCrypto.seal(kek, data)
        blob.ciphertext[0] = (blob.ciphertext[0].toInt() xor 1).toByte()
        try {
            KeyVaultCrypto.open(kek, blob)
            throw AssertionError("Expected KeyVaultException")
        } catch (e: KeyVaultException) {
        }
    }

    @Test
    fun wrongAadFails() {
        val blob = KeyVaultCrypto.seal(kek, data, "aad-one".toByteArray())
        try {
            KeyVaultCrypto.open(kek, blob, "aad-two".toByteArray())
            throw AssertionError("Expected KeyVaultException")
        } catch (_: KeyVaultException) {
        }
    }

    @Test
    fun kekCheckVerifies() {
        val check = KeyVaultCrypto.makeKekCheck(kek)
        assertTrue(KeyVaultCrypto.verifyKekCheck(kek, check))
        val wrong = CryptoRandom.bytes(32)
        assertFalse(KeyVaultCrypto.verifyKekCheck(wrong, check))
    }

    @Test
    fun deriveKekDeterministic() {
        val salt = CryptoRandom.bytes(KeyVaultCrypto.SALT_BYTES)
        val pw = "correct horse battery".toByteArray(Charsets.UTF_8)
        val k1 = KeyVaultCrypto.deriveKek(pw, salt)
        val k2 = KeyVaultCrypto.deriveKek(pw, salt)
        assertArrayEquals(k1, k2)
        assertEquals(KeyVaultCrypto.KEK_BYTES, k1.size)
    }

    @Test
    fun wrongPasswordFailsKekCheck() {
        val salt = CryptoRandom.bytes(KeyVaultCrypto.SALT_BYTES)
        val pw = "right-password-1".toByteArray(Charsets.UTF_8)
        val kekReal = KeyVaultCrypto.deriveKek(pw, salt)
        val check = KeyVaultCrypto.makeKekCheck(kekReal)

        val pwWrong = "wrong-password".toByteArray(Charsets.UTF_8)
        val kekWrong = KeyVaultCrypto.deriveKek(pwWrong, salt)
        if (kekWrong.contentEquals(kekReal)) throw AssertionError("KDF collision impossible")
        assertFalse(KeyVaultCrypto.verifyKekCheck(kekWrong, check))

        try {
            // эмулируем unlock: wrong password → verify fails → WrongPasswordException путь
            if (!KeyVaultCrypto.verifyKekCheck(kekWrong, check)) throw WrongPasswordException()
            throw AssertionError("Expected WrongPasswordException")
        } catch (_: WrongPasswordException) {
        }
    }
}
