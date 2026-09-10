package com.securetext.app.crypto.primitives

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object Ed25519 {
    fun sign(privateKeySeed: ByteArray, message: ByteArray): ByteArray {
        val privParams = Ed25519PrivateKeyParameters(privateKeySeed)
        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verify(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean {
        val pubParams = Ed25519PublicKeyParameters(publicKey)
        val verifier = Ed25519Signer()
        verifier.init(false, pubParams)
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    fun publicFromSeed(seed: ByteArray): ByteArray {
        val privParams = Ed25519PrivateKeyParameters(seed)
        return privParams.generatePublicKey().encoded
    }
}

