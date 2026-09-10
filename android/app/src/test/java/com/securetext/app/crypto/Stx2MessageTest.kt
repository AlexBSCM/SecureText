package com.securetext.app.crypto

import com.securetext.app.crypto.primitives.Ed25519
import com.securetext.app.crypto.primitives.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Stx2MessageTest {

    @Test
    fun testEncryptDecryptRoundtrip() {
        val senderEdSeed = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        val senderEdPub = Ed25519.publicFromSeed(senderEdSeed)
        val recipientXPriv = Hex.decode("0303030303030303030303030303030303030303030303030303030303030303")
        val recipientXPub = X25519.publicFromPrivate(recipientXPriv)
        val ephemeralPriv = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val nonce = ByteArray(24) { 0x10 }
        val plaintext = "Hello, Secure Text!".toByteArray(Charsets.UTF_8)

        val message = Stx2Message.encrypt(
            plaintext, recipientXPub, senderEdSeed, senderEdPub, ephemeralPriv, nonce
        )
        assertTrue(message.startsWith("STX2:"))

        val result = Stx2Message.decrypt(message, recipientXPriv)
        assertArrayEquals(plaintext, result.plaintext)
        assertArrayEquals(senderEdPub, result.senderEd25519Public)
    }

    @Test
    fun testPublicIdentityRoundtrip() {
        val edPub = Hex.decode("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
        val xPub = Hex.decode("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")

        val identity = Stx2Message.buildPublicIdentity(edPub, xPub)
        assertTrue(identity.startsWith("STX-PUB2:"))

        val parsed = Stx2Message.parsePublicIdentity(identity)
        assertArrayEquals(edPub, parsed.ed25519Public)
        assertArrayEquals(xPub, parsed.x25519Public)
    }

    @Test(expected = Stx2VersionException::class)
    fun testWrongVersionRejected() {
        val senderEdSeed = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        val senderEdPub = Ed25519.publicFromSeed(senderEdSeed)
        val recipientXPriv = Hex.decode("0303030303030303030303030303030303030303030303030303030303030303")
        val recipientXPub = X25519.publicFromPrivate(recipientXPriv)
        val ephemeralPriv = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val nonce = ByteArray(24) { 0x10 }
        val plaintext = "test".toByteArray(Charsets.UTF_8)

        val message = Stx2Message.encrypt(
            plaintext, recipientXPub, senderEdSeed, senderEdPub, ephemeralPriv, nonce
        )

        val payload = Base64Url.decode(message.substring(5))
        val jsonStr = String(payload, Charsets.UTF_8)
        val tamperedJson = jsonStr.replace("\"v\":2", "\"v\":3")
        val tamperedMsg = "STX2:" + Base64Url.encode(tamperedJson.toByteArray(Charsets.UTF_8))
        Stx2Message.decrypt(tamperedMsg, recipientXPriv)
    }

    @Test(expected = Stx2SignatureException::class)
    fun testTamperedSignatureRejected() {
        val senderEdSeed = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        val senderEdPub = Ed25519.publicFromSeed(senderEdSeed)
        val recipientXPriv = Hex.decode("0303030303030303030303030303030303030303030303030303030303030303")
        val recipientXPub = X25519.publicFromPrivate(recipientXPriv)
        val ephemeralPriv = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val nonce = ByteArray(24) { 0x10 }
        val plaintext = "test".toByteArray(Charsets.UTF_8)

        val message = Stx2Message.encrypt(
            plaintext, recipientXPub, senderEdSeed, senderEdPub, ephemeralPriv, nonce
        )

        val payload = Base64Url.decode(message.substring(5))
        val jsonStr = String(payload, Charsets.UTF_8)
        val tamperedJson = Regex("\"sig\":\"[^\"]*\"").replace(jsonStr, "\"sig\":\"" + "A".repeat(86) + "\"")
        val tamperedMsg = "STX2:" + Base64Url.encode(tamperedJson.toByteArray(Charsets.UTF_8))
        Stx2Message.decrypt(tamperedMsg, recipientXPriv)
    }
}

