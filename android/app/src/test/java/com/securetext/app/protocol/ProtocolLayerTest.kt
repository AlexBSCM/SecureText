package com.securetext.app.protocol

import com.securetext.app.crypto.Hex
import com.securetext.app.crypto.primitives.Ed25519
import com.securetext.app.crypto.primitives.X25519
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProtocolLayerTest {

    private val parser = Json { ignoreUnknownKeys = true }

    private fun loadVectors(): JsonObject {
        var dir: File? = File(System.getProperty("user.dir")!!).absoluteFile
        var found: File? = null
        repeat(8) {
            if (dir != null) {
                val candidate = File(dir, "test_vectors.json")
                if (candidate.isFile) {
                    found = candidate
                    return@repeat
                }
                dir = dir.parentFile
            }
        }
        assertTrue("test_vectors.json not found", found != null)
        return parser.parseToJsonElement(found!!.readText()).jsonObject
    }

    private fun JsonObject.obj(key: String): JsonObject = this[key]!!.jsonObject
    private fun JsonObject.str(key: String): String = this[key]!!.jsonPrimitive.content
    private fun JsonObject.hex(key: String): ByteArray = Hex.decode(str(key))

    private fun firstPositive(): JsonObject {
        val vectors = loadVectors()
        return vectors["positive_vectors"]!!.jsonArray.first().jsonObject
    }

    @Test
    fun encryptorProducesDecryptableRandomMessages() {
        val v = firstPositive()
        val sender = v.obj("sender")
        val recipient = v.obj("recipient")
        val plaintext = v.str("plaintext").toByteArray(Charsets.UTF_8)
        val recipientXPriv = recipient.hex("x25519_private_hex")
        val recipientXPub = recipient.hex("x25519_public_hex")
        val edSeed = sender.hex("ed25519_private_hex")
        val edPub = sender.hex("ed25519_public_hex")

        val m1 = Encryptor.encrypt(plaintext, recipientXPub, edSeed, edPub)
        val m2 = Encryptor.encrypt(plaintext, recipientXPub, edSeed, edPub)

        assertTrue(m1.startsWith("STX2:"))
        assertNotEquals("Random ephemeral+nonce must differ between encryptions", m1, m2)

        val r1 = Decryptor.decrypt(m1, recipientXPriv)
        val r2 = Decryptor.decrypt(m2, recipientXPriv)
        assertArrayEquals(plaintext, r1.plaintext)
        assertArrayEquals(plaintext, r2.plaintext)
        assertArrayEquals(edPub, r1.senderEd25519Public)
    }

    @Test
    fun decryptorOutcomeSuccessOnPositiveVectors() {
        val vectors = loadVectors()
        for (entry in vectors["positive_vectors"]!!.jsonArray) {
            val v = entry.jsonObject
            val recipient = v.obj("recipient")
            val outcome = Decryptor.decryptWithOutcome(
                v.str("expected_message"), recipient.hex("x25519_private_hex")
            )
            val success = outcome as DecryptOutcome.Success
            assertArrayEquals(
                v.str("plaintext").toByteArray(Charsets.UTF_8),
                success.result.plaintext
            )
        }
    }

    @Test
    fun decryptorOutcomeMapsNegativeVectors() {
        val vectors = loadVectors()
        for (entry in vectors["negative_vectors"]!!.jsonArray) {
            val v = entry.jsonObject
            val base = vectors["positive_vectors"]!!.jsonArray
                .first { it.jsonObject.str("name") == v.str("base_vector") }.jsonObject
            val recipient = base.obj("recipient")

            val outcome = Decryptor.decryptWithOutcome(
                v.str("mutated_message"), recipient.hex("x25519_private_hex")
            )
            val failure = outcome as? DecryptOutcome.Failure
                ?: throw AssertionError("Vector ${v.str("name")} unexpectedly decrypted")

            val expectedReason = when (v.str("expected")) {
                "DECRYPT_FAIL" -> DecryptFailureReason.DECRYPTION_FAILED
                "SIGNATURE_FAIL" -> DecryptFailureReason.SIGNATURE_INVALID
                "VERSION_FAIL" -> DecryptFailureReason.WRONG_VERSION
                else -> throw AssertionError("Unknown expected: ${v.str("expected")}")
            }
            assertEquals("Vector ${v.str("name")}", expectedReason, failure.reason)
        }
    }

    @Test
    fun detectorFindsMessageInText() {
        val v = firstPositive()
        val msg = v.str("expected_message")
        assertTrue(Stx2Detector.isStx2Message("Prefix text $msg suffix text"))
        assertEquals(msg, Stx2Detector.extract("Prefix text $msg suffix text"))
        assertEquals(msg, Stx2Detector.extract(msg))
        assertNull(Stx2Detector.extract("no message here"))
        assertNull(Stx2Detector.extract("STX2:"))
        assertNull(Stx2Detector.extract("STX1:AAAA"))
        assertTrue(Stx2Detector.isStx2Message("line1\n$msg\nline2"))
    }

    @Test
    fun fingerprintFormatMatchesSpec() {
        val v = firstPositive()
        val identity = v.obj("recipient").str("public_identity")
        val fp = Stx2Fingerprint.compute(identity)
        assertEquals(v.obj("recipient").str("fingerprint"), fp)
        val groups = fp.split(" ")
        assertEquals(Stx2Fingerprint.GROUPS, groups.size)
        assertTrue(groups.all { it.length == Stx2Fingerprint.GROUP_LENGTH && it == it.uppercase() })
    }
}
