package com.securetext.app.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull

object CanonicalJson {

    fun encode(obj: Map<String, JsonElement>): ByteArray =
        encodeString(obj).toByteArray(Charsets.UTF_8)

    fun encodeString(obj: Map<String, JsonElement>): String {
        val sb = StringBuilder("{")
        var first = true
        for ((key, value) in obj.toSortedMap()) {
            if (!first) sb.append(",")
            first = false
            sb.append('"').append(escapeJsonString(key)).append("\":")
            appendValue(sb, value)
        }
        sb.append("}")
        return sb.toString()
    }

    private fun appendValue(sb: StringBuilder, el: JsonElement) {
        when (el) {
            is JsonObject -> {
                sb.append('{')
                var first = true
                for ((k, v) in el.entries.sortedBy { it.key }) {
                    if (!first) sb.append(",")
                    first = false
                    sb.append('"').append(escapeJsonString(k)).append("\":")
                    appendValue(sb, v)
                }
                sb.append('}')
            }
            is JsonArray -> {
                sb.append('[')
                var first = true
                for (item in el) {
                    if (!first) sb.append(",")
                    first = false
                    appendValue(sb, item)
                }
                sb.append(']')
            }
            is JsonPrimitive -> {
                if (el.isString) {
                    sb.append('"').append(escapeJsonString(el.content)).append('"')
                } else {
                    sb.append(el.content)
                }
            }
            is JsonNull -> sb.append("null")
        }
    }

    internal fun escapeJsonString(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            val code = c.code
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                code < 0x20 || code == 0x7F -> {
                    sb.append("\\u")
                    sb.append(String.format("%04x", code))
                }
                code > 0x7F -> {
                    if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                        sb.append("\\u")
                        sb.append(String.format("%04x", c.code))
                        sb.append("\\u")
                        sb.append(String.format("%04x", s[i + 1].code))
                        i++
                    } else {
                        sb.append("\\u")
                        sb.append(String.format("%04x", code))
                    }
                }
                else -> sb.append(c)
            }
            i++
        }
        return sb.toString()
    }
}

