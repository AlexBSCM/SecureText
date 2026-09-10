package com.securetext.app.crypto

object Stx2Constants {
    const val MESSAGE_PREFIX = "STX2:"
    const val PUBLIC_KEY_PREFIX = "STX-PUB2:"
    const val VERSION = 2
    val AAD: ByteArray = "STX2".toByteArray(Charsets.UTF_8)
    const val HKDF_INFO = "SecureText v2 X25519 XChaCha20-Poly1305"
    const val HKDF_LENGTH = 32
    const val XCHACHA20_NONCE_BYTES = 24
    const val XCHACHA20_KEY_BYTES = 32
    const val ED25519_SIGNATURE_BYTES = 64
    const val ED25519_PUBLIC_KEY_BYTES = 32
    const val X25519_PUBLIC_KEY_BYTES = 32
    const val BACKUP_AAD = "SecureText private key v2"
    const val BACKUP_CHACHA20_NONCE_BYTES = 12
    const val ARGON2_TIME_COST = 3
    const val ARGON2_MEMORY_KIB = 65536
    const val ARGON2_PARALLELISM = 2
    const val ARGON2_HASH_LEN = 32
    const val ARGON2_SALT_BYTES = 16
}

