package com.securetext.app.crypto.primitives

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

object X25519 {
    fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(privateKey)
        return priv.generatePublicKey().encoded
    }

    fun computeSharedSecret(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(privateKey)
        val pub = X25519PublicKeyParameters(peerPublicKey)
        val out = ByteArray(32)
        priv.generateSecret(pub, out, 0)
        return out
    }
}

