package com.securetext.app.storage

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.securetext.app.crypto.Base64Url
import com.securetext.app.crypto.CryptoRandom
import com.securetext.app.crypto.SecureWipe
import com.securetext.app.crypto.Stx2Message
import com.securetext.app.crypto.keywrap.KeystoreKekWrapper
import com.securetext.app.crypto.keywrap.KeyVaultCrypto
import com.securetext.app.crypto.keywrap.KeyVaultException
import com.securetext.app.crypto.keywrap.WrongPasswordException
import com.securetext.app.crypto.primitives.Ed25519
import com.securetext.app.crypto.primitives.X25519
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import javax.inject.Inject
import javax.inject.Singleton

private val Context.identityDataStore by preferencesDataStore(name = "secure_text_identity")

class IdentityExistsException : Exception("Identity already exists")
class IdentityNotExistsException : Exception("Identity not found")
class VaultLockedException : Exception("Vault is locked")

@Singleton
class IdentityStore @Inject constructor(
    @ApplicationContext private val context: Context,
    private val keystoreKekWrapper: KeystoreKekWrapper
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val prefKey = stringPreferencesKey("identity_json")
    private val mutex = Mutex()

    private val _state = MutableStateFlow<VaultState>(VaultState.Loading)
    val state: StateFlow<VaultState> = _state.asStateFlow()

    @Volatile private var cachedKek: ByteArray? = null
    @Volatile private var cachedX25519Private: ByteArray? = null
    @Volatile private var cachedEd25519Private: ByteArray? = null

    suspend fun initialize() {
        mutex.withLock {
            if (_state.value != VaultState.Loading) return
            _state.value = if (readRecord() != null) VaultState.Locked else VaultState.NoIdentity
        }
    }

    suspend fun hasIdentity(): Boolean = readRecord() != null

    suspend fun getRecord(): IdentityRecordDto? = readRecord()

    fun isUnlocked(): Boolean = _state.value == VaultState.Unlocked

    suspend fun createIdentity(password: ByteArray) {
        mutex.withLock {
            if (readRecord() != null) throw IdentityExistsException()
            if (password.size < MIN_PASSWORD_BYTES) throw KeyVaultException("Password too short")

            val salt = CryptoRandom.bytes(KeyVaultCrypto.SALT_BYTES)
            val kek = KeyVaultCrypto.deriveKek(password, salt)

            val x25519Priv = X25519PrivateKeyParameters(CryptoRandom.secure()).encoded
            val ed25519Seed = Ed25519PrivateKeyParameters(CryptoRandom.secure()).encoded
            val x25519Pub = X25519.publicFromPrivate(x25519Priv)
            val ed25519Pub = Ed25519.publicFromSeed(ed25519Seed)

            val xSealed = KeyVaultCrypto.seal(kek, x25519Priv)
            val edSealed = KeyVaultCrypto.seal(kek, ed25519Seed)
            val kekCheck = KeyVaultCrypto.makeKekCheck(kek)

            SecureWipe.wipe(x25519Priv, ed25519Seed)

            val wrapped = try {
                keystoreKekWrapper.wrapKekOrNull(kek)?.let {
                    WrappedKekDto(Base64Url.encode(it.iv), Base64Url.encode(it.ciphertext))
                }
            } catch (_: Exception) {
                null
            }

            val record = IdentityRecordDto(
                kdfSalt = Base64Url.encode(salt),
                x25519Private = SealedBlobDto.fromBlob(xSealed),
                ed25519Private = SealedBlobDto.fromBlob(edSealed),
                kekCheck = SealedBlobDto.fromBlob(kekCheck),
                x25519Public = Base64Url.encode(x25519Pub),
                ed25519Public = Base64Url.encode(ed25519Pub),
                wrappedKek = wrapped
            )

            saveRecord(record)

            cachedKek = kek.copyOf()
            cachedX25519Private = KeyVaultCrypto.open(kek, xSealed)
            cachedEd25519Private = KeyVaultCrypto.open(kek, edSealed)

            SecureWipe.wipe(kek)
            _state.value = VaultState.Unlocked
        }
    }

    suspend fun unlockWithPassword(password: ByteArray) {
        mutex.withLock {
            val record = readRecord() ?: throw IdentityNotExistsException()
            val kek = KeyVaultCrypto.deriveKek(password, record.kdfSaltBytes())

            if (!KeyVaultCrypto.verifyKekCheck(kek, record.kekCheck.toBlob())) {
                SecureWipe.wipe(kek)
                throw WrongPasswordException()
            }

            try {
                cachedKek = kek.copyOf()
                cachedX25519Private = KeyVaultCrypto.open(kek, record.x25519Private.toBlob())
                cachedEd25519Private = KeyVaultCrypto.open(kek, record.ed25519Private.toBlob())
            } catch (e: KeyVaultException) {
                SecureWipe.wipe(kek)
                cachedKek = null
                throw e
            }

            refreshWrappedKekLocked(record, kek)
            SecureWipe.wipe(kek)
            _state.value = VaultState.Unlocked
        }
    }

    suspend fun unlockWithKek(kek: ByteArray) {
        mutex.withLock {
            val record = readRecord() ?: throw IdentityNotExistsException()
            if (!KeyVaultCrypto.verifyKekCheck(kek, record.kekCheck.toBlob())) {
                SecureWipe.wipe(kek)
                throw KeyVaultException("Unwrapped KEK failed kek_check")
            }
            cachedKek = kek.copyOf()
            cachedX25519Private = KeyVaultCrypto.open(kek, record.x25519Private.toBlob())
            cachedEd25519Private = KeyVaultCrypto.open(kek, record.ed25519Private.toBlob())
            SecureWipe.wipe(kek)
            _state.value = VaultState.Unlocked
        }
    }

    suspend fun requireX25519Private(): ByteArray =
        cachedX25519Private?.copyOf() ?: throw VaultLockedException()

    suspend fun requireEd25519Private(): ByteArray =
        cachedEd25519Private?.copyOf() ?: throw VaultLockedException()

    suspend fun publicIdentity(): String {
        val record = readRecord() ?: throw IdentityNotExistsException()
        return Stx2Message.buildPublicIdentity(
            record.ed25519PublicBytes(), record.x25519PublicBytes()
        )
    }

    suspend fun fingerprint(): String = Stx2Message.fingerprint(publicIdentity())

    fun lock() {
        SecureWipe.wipe(cachedKek, cachedX25519Private, cachedEd25519Private)
        cachedKek = null
        cachedX25519Private = null
        cachedEd25519Private = null
        if (_state.value == VaultState.Unlocked) {
            _state.value = VaultState.Locked
        }
    }

    private suspend fun refreshWrappedKekLocked(record: IdentityRecordDto, kek: ByteArray) {
        try {
            val wrapped = keystoreKekWrapper.wrapKekOrNull(kek)
            if (wrapped != null) {
                val dto = WrappedKekDto(Base64Url.encode(wrapped.iv), Base64Url.encode(wrapped.ciphertext))
                if (record.wrappedKek != dto) {
                    saveRecord(record.copy(wrappedKek = dto))
                }
            }
        } catch (_: Exception) {
        }
    }

    private suspend fun readRecord(): IdentityRecordDto? {
        val prefs = context.identityDataStore.data.first()
        val raw = prefs[prefKey] ?: return null
        return try {
            json.decodeFromString(IdentityRecordDto.serializer(), raw)
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun saveRecord(record: IdentityRecordDto) {
        context.identityDataStore.edit { prefs ->
            prefs[prefKey] = json.encodeToString(IdentityRecordDto.serializer(), record)
        }
    }

    companion object {
        const val MIN_PASSWORD_BYTES = 8
    }
}
