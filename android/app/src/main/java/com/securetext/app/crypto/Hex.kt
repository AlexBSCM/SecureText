package com.securetext.app.crypto

object Hex {
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_CHARS[v ushr 4])
            sb.append(HEX_CHARS[v and 0x0F])
        }
        return sb.toString()
    }

    fun decode(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Odd hex length" }
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex char" }
            ((hi shl 4) or lo).toByte()
        }
    }
}

