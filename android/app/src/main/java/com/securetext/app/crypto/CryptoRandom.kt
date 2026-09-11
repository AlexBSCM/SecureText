package com.securetext.app.crypto

import java.security.SecureRandom

object CryptoRandom {
    private val rng = SecureRandom()

    fun secure(): SecureRandom = rng

    fun bytes(n: Int): ByteArray {
        val b = ByteArray(n)
        rng.nextBytes(b)
        return b
    }
}

