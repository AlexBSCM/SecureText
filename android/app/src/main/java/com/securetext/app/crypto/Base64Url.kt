package com.securetext.app.crypto

import java.util.Base64

object Base64Url {
    fun encode(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
    fun decode(s: String): ByteArray = Base64.getUrlDecoder().decode(s)
}

