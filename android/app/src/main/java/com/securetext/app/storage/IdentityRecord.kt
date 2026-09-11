package com.securetext.app.storage

import com.securetext.app.crypto.Base64Url
import com.securetext.app.crypto.keywrap.SealedBlob
import kotlinx.serialization.Serializable

@Serializable
data class SealedBlobDto(val nonce: String, val ciphertext: String) {
    fun toBlob(): SealedBlob = SealedBlob(Base64Url.decode(nonce), Base64Url.decode(ciphertext))
    companion object {
        fun fromBlob(blob: SealedBlob): SealedBlobDto =
            SealedBlobDto(Base64Url.encode(blob.nonce), Base64Url.encode(blob.ciphertext))
    }
}

@Serializable
data class WrappedKekDto(val iv: String, val ciphertext: String)

@Serializable
data class IdentityRecordDto(
    val version: Int = 2,
    val kdfSalt: String,
    val x25519Private: SealedBlobDto,
    val ed25519Private: SealedBlobDto,
    val kekCheck: SealedBlobDto,
    val x25519Public: String,
    val ed25519Public: String,
    val wrappedKek: WrappedKekDto? = null
) {
    fun kdfSaltBytes(): ByteArray = Base64Url.decode(kdfSalt)
    fun x25519PublicBytes(): ByteArray = Base64Url.decode(x25519Public)
    fun ed25519PublicBytes(): ByteArray = Base64Url.decode(ed25519Public)
}
