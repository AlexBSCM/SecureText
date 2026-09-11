package com.securetext.app.crypto.primitives

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

object ChaCha20Poly1305Ietf {
    const val NONCE_BYTES = 12
    private const val TAG_BITS = 128

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "IETF nonce must be $NONCE_BYTES bytes" }
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(plaintext.size + TAG_BITS / 8)
        val len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        cipher.doFinal(out, len)
        return out
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "IETF nonce must be $NONCE_BYTES bytes" }
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(ciphertextWithTag.size - TAG_BITS / 8)
        val len = cipher.processBytes(ciphertextWithTag, 0, ciphertextWithTag.size, out, 0)
        cipher.doFinal(out, len)
        return out
    }
}
