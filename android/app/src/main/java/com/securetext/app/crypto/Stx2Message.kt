package com.securetext.app.crypto

import com.securetext.app.crypto.primitives.Ed25519
import com.securetext.app.crypto.primitives.HkdfSha256
import com.securetext.app.crypto.primitives.X25519
import com.securetext.app.crypto.primitives.XChaCha20Poly1305Cipher
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import org.bouncycastle.crypto.digests.SHA256Digest

class Stx2FormatException(message: String) : Exception(message)
class Stx2VersionException(message: String) : Exception(message)
class Stx2SignatureException(message: String) : Exception(message)
class Stx2DecryptionException(message: String) : Exception(message)

data class DecryptionResult(val plaintext: ByteArray, val senderEd25519Public: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DecryptionResult) return false
        return plaintext.contentEquals(other.plaintext) && senderEd25519Public.contentEquals(other.senderEd25519Public)
    }
    override fun hashCode(): Int = plaintext.contentHashCode() * 31 + senderEd25519Public.contentHashCode()
}

object Stx2Message {
    private val jsonParser = Json { ignoreUnknownKeys = true }

    fun encrypt(
        plaintext: ByteArray,
        recipientX25519Public: ByteArray,
        senderEd25519Private: ByteArray,
        senderEd25519Public: ByteArray,
        ephemeralPrivate: ByteArray,
        nonce: ByteArray
    ): String {
        val ephemeralPublic = X25519.publicFromPrivate(ephemeralPrivate)
        val shared = X25519.computeSharedSecret(ephemeralPrivate, recipientX25519Public)
        val messageKey = HkdfSha256.deriveMessageKey(shared)
        val ct = XChaCha20Poly1305Cipher.encrypt(messageKey, nonce, plaintext, Stx2Constants.AAD)

        val unsignedMap = linkedMapOf<String, JsonElement>(
            "ct" to JsonPrimitive(Base64Url.encode(ct)),
            "epk" to JsonPrimitive(Base64Url.encode(ephemeralPublic)),
            "nonce" to JsonPrimitive(Base64Url.encode(nonce)),
            "sender_ed25519" to JsonPrimitive(Base64Url.encode(senderEd25519Public)),
            "v" to JsonPrimitive(Stx2Constants.VERSION)
        )
        val canonicalUnsigned = CanonicalJson.encode(unsignedMap)
        val sig = Ed25519.sign(senderEd25519Private, canonicalUnsigned)

        val fullMap = linkedMapOf<String, JsonElement>(
            "ct" to JsonPrimitive(Base64Url.encode(ct)),
            "epk" to JsonPrimitive(Base64Url.encode(ephemeralPublic)),
            "nonce" to JsonPrimitive(Base64Url.encode(nonce)),
            "sender_ed25519" to JsonPrimitive(Base64Url.encode(senderEd25519Public)),
            "sig" to JsonPrimitive(Base64Url.encode(sig)),
            "v" to JsonPrimitive(Stx2Constants.VERSION)
        )
        val canonicalFull = CanonicalJson.encode(fullMap)
        return Stx2Constants.MESSAGE_PREFIX + Base64Url.encode(canonicalFull)
    }

    fun decrypt(
        message: String,
        recipientX25519Private: ByteArray
    ): DecryptionResult {
        if (!message.startsWith(Stx2Constants.MESSAGE_PREFIX)) {
            throw Stx2FormatException("Missing STX2: prefix")
        }
        val b64Payload = message.substring(Stx2Constants.MESSAGE_PREFIX.length)
        val jsonBytes = try {
            Base64Url.decode(b64Payload)
        } catch (e: Exception) {
            throw Stx2FormatException("Invalid base64url: ${e.message}")
        }
        val jsonStr = String(jsonBytes, Charsets.UTF_8)
        val obj = try {
            jsonParser.parseToJsonElement(jsonStr) as JsonObject
        } catch (e: Exception) {
            throw Stx2FormatException("Invalid JSON: ${e.message}")
        }

        val v = obj["v"]?.let { (it as? JsonPrimitive)?.intOrNull }
        if (v != Stx2Constants.VERSION) {
            throw Stx2VersionException("Unsupported version: $v")
        }

        val epkB64 = (obj["epk"] as? JsonPrimitive)?.contentOrNull
            ?: throw Stx2FormatException("Missing epk")
        val nonceB64 = (obj["nonce"] as? JsonPrimitive)?.contentOrNull
            ?: throw Stx2FormatException("Missing nonce")
        val ctB64 = (obj["ct"] as? JsonPrimitive)?.contentOrNull
            ?: throw Stx2FormatException("Missing ct")
        val senderEdB64 = (obj["sender_ed25519"] as? JsonPrimitive)?.contentOrNull
            ?: throw Stx2FormatException("Missing sender_ed25519")
        val sigB64 = (obj["sig"] as? JsonPrimitive)?.contentOrNull
            ?: throw Stx2FormatException("Missing sig")

        val epk = Base64Url.decode(epkB64)
        val nonce = Base64Url.decode(nonceB64)
        val ct = Base64Url.decode(ctB64)
        val senderEd = Base64Url.decode(senderEdB64)
        val sig = Base64Url.decode(sigB64)

        val shared = X25519.computeSharedSecret(recipientX25519Private, epk)
        val messageKey = HkdfSha256.deriveMessageKey(shared)

        val plaintext = try {
            XChaCha20Poly1305Cipher.decrypt(messageKey, nonce, ct, Stx2Constants.AAD)
        } catch (e: Exception) {
            throw Stx2DecryptionException("XChaCha20-Poly1305 decryption failed: ${e.message}")
        }

        val unsignedMap = linkedMapOf<String, JsonElement>(
            "ct" to JsonPrimitive(ctB64),
            "epk" to JsonPrimitive(epkB64),
            "nonce" to JsonPrimitive(nonceB64),
            "sender_ed25519" to JsonPrimitive(senderEdB64),
            "v" to JsonPrimitive(Stx2Constants.VERSION)
        )
        val canonicalUnsigned = CanonicalJson.encode(unsignedMap)

        if (!Ed25519.verify(senderEd, sig, canonicalUnsigned)) {
            throw Stx2SignatureException("Invalid Ed25519 signature")
        }

        return DecryptionResult(plaintext, senderEd)
    }

    fun buildPublicIdentity(ed25519Public: ByteArray, x25519Public: ByteArray): String {
        val map = linkedMapOf<String, JsonElement>(
            "ed25519" to JsonPrimitive(Base64Url.encode(ed25519Public)),
            "v" to JsonPrimitive(Stx2Constants.VERSION),
            "x25519" to JsonPrimitive(Base64Url.encode(x25519Public))
        )
        val canonical = CanonicalJson.encode(map)
        return Stx2Constants.PUBLIC_KEY_PREFIX + Base64Url.encode(canonical)
    }

    data class PublicIdentity(val ed25519Public: ByteArray, val x25519Public: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PublicIdentity) return false
            return ed25519Public.contentEquals(other.ed25519Public) && x25519Public.contentEquals(other.x25519Public)
        }
        override fun hashCode(): Int = ed25519Public.contentHashCode() * 31 + x25519Public.contentHashCode()
    }

    fun parsePublicIdentity(identity: String): PublicIdentity {
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

    fun fingerprint(identity: String): String {
        if (!identity.startsWith(Stx2Constants.PUBLIC_KEY_PREFIX)) {
            throw Stx2FormatException("Missing STX-PUB2: prefix")
        }
        val b64 = identity.substring(Stx2Constants.PUBLIC_KEY_PREFIX.length)
        val jsonBytes = Base64Url.decode(b64)
        val digest = SHA256Digest()
        digest.update(jsonBytes, 0, jsonBytes.size)
        val hash = ByteArray(32)
        digest.doFinal(hash, 0)
        val hex = Hex.encode(hash.take(16).toByteArray()).uppercase()
        return hex.chunked(4).joinToString(" ")
    }
}

