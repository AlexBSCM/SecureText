package com.securetext.app.crypto.primitives

import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

object XChaCha20Poly1305Cipher {
    private const val TAG_BITS = 128

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = XChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(plaintext.size + TAG_BITS / 8)
        val len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        cipher.doFinal(out, len)
        return out
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        val cipher = XChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(ciphertextWithTag.size - TAG_BITS / 8)
        val len = cipher.processBytes(ciphertextWithTag, 0, ciphertextWithTag.size, out, 0)
        cipher.doFinal(out, len)
        return out
    }
}

