package com.securetext.app.crypto.argon2

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import com.securetext.app.crypto.Stx2Constants

object Argon2id {
    fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray = deriveKey(
        password, salt,
        Stx2Constants.ARGON2_TIME_COST,
        Stx2Constants.ARGON2_MEMORY_KIB,
        Stx2Constants.ARGON2_PARALLELISM,
        Stx2Constants.ARGON2_HASH_LEN
    )

    fun deriveKey(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        hashLen: Int
    ): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memoryKiB)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(hashLen)
        gen.generateBytes(password, out)
        return out
    }
}

