package com.securetext.app.protocol

import com.securetext.app.crypto.Base64Url
import com.securetext.app.crypto.Hex
import com.securetext.app.crypto.Stx2Constants
import org.bouncycastle.crypto.digests.SHA256Digest

object Stx2Fingerprint {
    const val GROUPS = 8
    const val GROUP_LENGTH = 4

    fun compute(publicIdentity: String): String {
        if (!publicIdentity.startsWith(Stx2Constants.PUBLIC_KEY_PREFIX)) {
            throw Stx2FormatException("Missing STX-PUB2: prefix")
        }
        val b64 = publicIdentity.substring(Stx2Constants.PUBLIC_KEY_PREFIX.length)
        val jsonBytes = Base64Url.decode(b64)
        val digest = SHA256Digest()
        digest.update(jsonBytes, 0, jsonBytes.size)
        val hash = ByteArray(32)
        digest.doFinal(hash, 0)
        val hex = Hex.encode(hash.take(16).toByteArray()).uppercase()
        return hex.chunked(GROUP_LENGTH).joinToString(" ")
    }
}
