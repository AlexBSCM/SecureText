package com.securetext.app.crypto

import com.securetext.app.crypto.argon2.Argon2id
import com.securetext.app.crypto.primitives.Ed25519
import com.securetext.app.crypto.primitives.HkdfSha256
import com.securetext.app.crypto.primitives.X25519
import com.securetext.app.crypto.primitives.XChaCha20Poly1305Cipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoPrimitivesTest {

    @Test
    fun testX25519Rfc7748() {
        val alicePriv = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePub = Hex.decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPriv = Hex.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPub = Hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val expectedShared = Hex.decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertArrayEquals(alicePub, X25519.publicFromPrivate(alicePriv))
        assertArrayEquals(bobPub, X25519.publicFromPrivate(bobPriv))
        assertArrayEquals(expectedShared, X25519.computeSharedSecret(alicePriv, bobPub))
        assertArrayEquals(expectedShared, X25519.computeSharedSecret(bobPriv, alicePub))
    }

    @Test
    fun testEd25519Rfc8032Vector1() {
        val seed = Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val expectedPub = Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val msg = ByteArray(0)
        val expectedSig = Hex.decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        assertArrayEquals(expectedPub, Ed25519.publicFromSeed(seed))
        val sig = Ed25519.sign(seed, msg)
        assertArrayEquals(expectedSig, sig)
        assertTrue(Ed25519.verify(expectedPub, sig, msg))
    }

    @Test
    fun testXChaCha20Poly1305PythonVector() {
        val key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = Hex.decode("404142434445464748494a4b4c4d4e4f5051525354555657")
        val aad = Hex.decode("50515253c0c1c2c3c4c5c6c7")
        val pt = ("Ladies and Gentlemen of the class of '99: " +
                "If I could offer you only one tip for the future, sunscreen would be it.")
            .toByteArray(Charsets.US_ASCII)
        val expectedCt = Hex.decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        )

        val ct = XChaCha20Poly1305Cipher.encrypt(key, nonce, pt, aad)
        assertArrayEquals(expectedCt, ct)

        val decrypted = XChaCha20Poly1305Cipher.decrypt(key, nonce, ct, aad)
        assertArrayEquals(pt, decrypted)
    }

    @Test
    fun testHkdfSha256Stx2() {
        val ikm = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val expectedOkm = Hex.decode("04b8e602649b3d37619606217803daa42080ec684597b942a0d11743755903de")

        val okm = HkdfSha256.deriveMessageKey(ikm)
        assertArrayEquals(expectedOkm, okm)
    }

    @Test
    fun testHkdfSha256Rfc5869Case1() {
        val ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = Hex.decode("000102030405060708090a0b0c")
        val info = Hex.decode("f0f1f2f3f4f5f6f7f8f9")
        val expectedOkm = Hex.decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )

        val okm = HkdfSha256.derive(ikm, salt, info, 42)
        assertArrayEquals(expectedOkm, okm)
    }

    @Test
    fun testArgon2idPythonVector() {
        val pw = "STX2 test password".toByteArray(Charsets.UTF_8)
        val salt = Hex.decode("000102030405060708090a0b0c0d0e0f")
        val expected = Hex.decode("01ce6f1b9957526512fed40827556d24deaa140e7f37c98dc8baf593234eb4b2")

        val hash = Argon2id.deriveKey(pw, salt)
        assertArrayEquals(expected, hash)
    }

    @Test
    fun testBase64UrlRoundtrip() {
        val data = byteArrayOf(0, 1, 2, 255.toByte(), 254.toByte())
        val encoded = Base64Url.encode(data)
        assertTrue(!encoded.contains("="))
        assertTrue(!encoded.contains("+"))
        assertTrue(!encoded.contains("/"))
        assertArrayEquals(data, Base64Url.decode(encoded))
    }

    @Test
    fun testHexRoundtrip() {
        val data = byteArrayOf(0x0a, 0xff.toByte(), 0x00, 0x42)
        assertEquals("0aff0042", Hex.encode(data))
        assertArrayEquals(data, Hex.decode("0aff0042"))
    }

    @Test
    fun testCanonicalJsonEdgeCases() {
        val jsonStr = "{\"a\":\"x\",\"arr\":[\"s\",1,null],\"b\":true,\"emoji\":\"\\ud83d\\ude00\",\"m\":\"\\n\\t\\\"\",\"n\":2,\"obj\":{\"k\":\"v\"},\"z\":\"\\u00e9\\u4f60\\u597d\"}"
        val obj = kotlinx.serialization.json.Json.parseToJsonElement(jsonStr) as kotlinx.serialization.json.JsonObject
        val canonical = CanonicalJson.encodeString(obj)
        assertEquals(jsonStr, canonical)
    }

    @Test
    fun testCanonicalJsonControlChars() {
        val jsonStr = "{\"c\":\"\\u0000\\u0001\\u001f\\u007f\"}"
        val obj = kotlinx.serialization.json.Json.parseToJsonElement(jsonStr) as kotlinx.serialization.json.JsonObject
        val canonical = CanonicalJson.encodeString(obj)
        assertEquals(jsonStr, canonical)
    }
}

