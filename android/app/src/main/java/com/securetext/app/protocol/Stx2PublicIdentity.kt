package com.securetext.app.protocol

import com.securetext.app.crypto.Base64Url
import com.securetext.app.crypto.CanonicalJson
import com.securetext.app.crypto.Stx2Constants
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class PublicIdentity(val ed25519Public: ByteArray, val x25519Public: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PublicIdentity) return false
        return ed25519Public.contentEquals(other.ed25519Public) && x25519Public.contentEquals(other.x25519Public)
    }
    override fun hashCode(): Int = ed25519Public.contentHashCode() * 31 + x25519Public.contentHashCode()
}

object Stx2PublicIdentity {
    private val jsonParser = Json { ignoreUnknownKeys = true }

    fun build(ed25519Public: ByteArray, x25519Public: ByteArray): String {
        val map = linkedMapOf<String, JsonElement>(
            "ed25519" to JsonPrimitive(Base64Url.encode(ed25519Public)),
            "v" to JsonPrimitive(Stx2Constants.VERSION),
            "x25519" to JsonPrimitive(Base64Url.encode(x25519Public))
        )
        val canonical = CanonicalJson.encode(map)
        return Stx2Constants.PUBLIC_KEY_PREFIX + Base64Url.encode(canonical)
    }

    fun encode(identity: PublicIdentity): String =
        build(identity.ed25519Public, identity.x25519Public)

    fun parse(identity: String): PublicIdentity {
        if (!identity.startsWith(Stx2Constants.PUBLIC_KEY_PREFIX)) {
            throw Stx2FormatException("Missing STX-PUB2: prefix")
        }
        val b64 = identity.substring(Stx2Constants.PUBLIC_KEY_PREFIX.length)
        val jsonBytes = Base64Url.decode(b64)
        val jsonStr = String(jsonBytes, Charsets.UTF_8)
        val obj = jsonParser.parseToJsonElement(jsonStr) as JsonObject
        val ed = Base64Url.decode((obj["ed25519"] as JsonPrimitive).content)
        val x = Base64Url.decode((obj["x25519"] as JsonPrimitive).content)
        return PublicIdentity(ed, x)
    }
}
