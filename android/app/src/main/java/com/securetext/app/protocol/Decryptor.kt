package com.securetext.app.protocol

enum class DecryptFailureReason {
    BAD_FORMAT,
    WRONG_VERSION,
    DECRYPTION_FAILED,
    SIGNATURE_INVALID
}

sealed interface DecryptOutcome {
    data class Success(val result: DecryptionResult) : DecryptOutcome
    data class Failure(val reason: DecryptFailureReason, val detail: String? = null) : DecryptOutcome
}

object Decryptor {
    fun decrypt(
        message: String,
        recipientX25519Private: ByteArray
    ): DecryptionResult = Stx2Message.decrypt(message, recipientX25519Private)

    fun decryptWithOutcome(
        message: String,
        recipientX25519Private: ByteArray
    ): DecryptOutcome = try {
        DecryptOutcome.Success(Stx2Message.decrypt(message, recipientX25519Private))
    } catch (e: Stx2FormatException) {
        DecryptOutcome.Failure(DecryptFailureReason.BAD_FORMAT, e.message)
    } catch (e: Stx2VersionException) {
        DecryptOutcome.Failure(DecryptFailureReason.WRONG_VERSION, e.message)
    } catch (e: Stx2DecryptionException) {
        DecryptOutcome.Failure(DecryptFailureReason.DECRYPTION_FAILED, e.message)
    } catch (e: Stx2SignatureException) {
        DecryptOutcome.Failure(DecryptFailureReason.SIGNATURE_INVALID, e.message)
    }
}
