package com.securetext.app.protocol

import com.securetext.app.crypto.Stx2Constants

object Stx2Detector {
    fun isStx2Message(text: String): Boolean {
        return extract(text) != null
    }

    fun extract(text: String): String? {
        return text.split(WHITESPACE)
            .firstOrNull { it.startsWith(Stx2Constants.MESSAGE_PREFIX) && it.length > Stx2Constants.MESSAGE_PREFIX.length }
    }

    private val WHITESPACE = Regex("\\s+")
}
