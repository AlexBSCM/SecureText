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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class TestVectorsCrossCheckTest {

    private val parser = Json { ignoreUnknownKeys = true }

    private fun loadTestVectors(): JsonObject {
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

    private val vectors: JsonObject by lazy { loadTestVectors() }

    @Test
    fun testPositiveEncryptAllVectors() {
        for (name in vectors["positive_vectors"]!!.jsonArray) {
            val v = name.jsonObject
            val sender = v.obj("sender")
            val recipient = v.obj("recipient")
            val plaintext = v.str("plaintext").toByteArray(Charsets.UTF_8)

            val message = Stx2Message.encrypt(
                plaintext,
                recipient.hex("x25519_public_hex"),
                sender.hex("ed25519_private_hex"),
                sender.hex("ed25519_public_hex"),
                v.hex("ephemeral_private_hex"),
                v.hex("nonce_hex")
            )

            assertEquals("Encrypt mismatch for ${v.str("name")}", v.str("expected_message"), message)
        }
    }

    @Test
    fun testPositiveDecryptAllVectors() {
        for (name in vectors["positive_vectors"]!!.jsonArray) {
            val v = name.jsonObject
            val recipient = v.obj("recipient")
            val sender = v.obj("sender")
            val expectedPlaintext = v.str("plaintext").toByteArray(Charsets.UTF_8)

            val result = Stx2Message.decrypt(v.str("expected_message"), recipient.hex("x25519_private_hex"))

            assertArrayEquals("Plaintext mismatch for ${v.str("name")}", expectedPlaintext, result.plaintext)
            assertArrayEquals(
                "Sender pub mismatch for ${v.str("name")}",
                sender.hex("ed25519_public_hex"),
                result.senderEd25519Public
            )
        }
    }

    @Test
    fun testPublicIdentityAllVectors() {
        for (name in vectors["positive_vectors"]!!.jsonArray) {
            val v = name.jsonObject
            val recipient = v.obj("recipient")
            val edPub = recipient.hex("ed25519_public_hex")
            val xPub = recipient.hex("x25519_public_hex")

            val identity = Stx2PublicIdentity.build(edPub, xPub)
            assertEquals("Identity mismatch for ${v.str("name")}", recipient.str("public_identity"), identity)

            val fp = Stx2Fingerprint.compute(identity)
            assertEquals("Fingerprint mismatch for ${v.str("name")}", recipient.str("fingerprint"), fp)

            val parsed = Stx2PublicIdentity.parse(identity)
            assertArrayEquals(edPub, parsed.ed25519Public)
            assertArrayEquals(xPub, parsed.x25519Public)
        }
    }

    @Test
    fun testNegativeAllVectors() {
        var checked = 0
        for (entry in vectors["negative_vectors"]!!.jsonArray) {
            val v = entry.jsonObject
            val base = vectors["positive_vectors"]!!.jsonArray.first {
                it.jsonObject.str("name") == v.str("base_vector")
            }.jsonObject
            val recipient = base.obj("recipient")

            val expected: Class<*>
            val description: String
            when (v.str("expected")) {
                "DECRYPT_FAIL" -> {
                    expected = Stx2DecryptionException::class.java
                    description = "decryption"
                }
                "SIGNATURE_FAIL" -> {
                    expected = Stx2SignatureException::class.java
                    description = "signature"
                }
                "VERSION_FAIL" -> {
                    expected = Stx2VersionException::class.java
                    description = "version"
                }
                else -> throw IllegalStateException("Unknown expected: ${v.str("expected")}")
            }

            try {
                Stx2Message.decrypt(v.str("mutated_message"), recipient.hex("x25519_private_hex"))
                throw AssertionError(
                    "Negative vector ${v.str("name")} should fail $description but decrypted successfully"
                )
            } catch (e: Exception) {
                assertTrue(
                    "Vector ${v.str("name")}: expected $expected but got ${e::class.java} (${e.message})",
                    expected.isInstance(e)
                )
            }
            checked++
        }
        assertTrue("No negative vectors checked", checked > 0)
    }
}
