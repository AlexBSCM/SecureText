package com.securetext.app.protocol

object Encryptor {
    fun encrypt(
        plaintext: ByteArray,
        recipientX25519Public: ByteArray,
        senderEd25519Private: ByteArray,
        senderEd25519Public: ByteArray
    ): String = Stx2Message.encrypt(
        plaintext, recipientX25519Public, senderEd25519Private, senderEd25519Public
    )
}
