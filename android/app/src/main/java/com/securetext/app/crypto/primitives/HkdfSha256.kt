package com.securetext.app.crypto.primitives

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import com.securetext.app.crypto.Stx2Constants

object HkdfSha256 {
    fun deriveMessageKey(sharedSecret: ByteArray): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val salt = ByteArray(32)
        val info = Stx2Constants.HKDF_INFO.toByteArray(Charsets.UTF_8)
        hkdf.init(HKDFParameters(sharedSecret, salt, info))
        val out = ByteArray(Stx2Constants.HKDF_LENGTH)
        hkdf.generateBytes(out, 0, out.size)
        return out
    }

    fun derive(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val effectiveSalt = salt ?: ByteArray(32)
        hkdf.init(HKDFParameters(ikm, effectiveSalt, info))
        val out = ByteArray(length)
        hkdf.generateBytes(out, 0, out.size)
        return out
    }
}

