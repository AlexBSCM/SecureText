package com.securetext.app.ui.vault

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securetext.app.crypto.Base64Url
import com.securetext.app.crypto.SecureWipe
import com.securetext.app.crypto.keywrap.KeystoreKekWrapper
import com.securetext.app.crypto.keywrap.KekWrapException
import com.securetext.app.crypto.keywrap.WrongPasswordException
import com.securetext.app.security.BiometricResult
import com.securetext.app.security.BiometricUnlock
import com.securetext.app.storage.IdentityExistsException
import com.securetext.app.storage.IdentityStore
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface CreatePasswordUiState {
    data object Idle : CreatePasswordUiState
    data object Working : CreatePasswordUiState
    data class Error(val message: String) : CreatePasswordUiState
}

sealed interface UnlockUiState {
    data object Idle : UnlockUiState
    data object Working : UnlockUiState
    data class Error(val message: String) : UnlockUiState
}

@HiltViewModel
class CreatePasswordViewModel @Inject constructor(
    private val identityStore: IdentityStore
) : ViewModel() {

    private val _uiState = MutableStateFlow<CreatePasswordUiState>(CreatePasswordUiState.Idle)
    val uiState: StateFlow<CreatePasswordUiState> = _uiState.asStateFlow()

    fun create(password: String, confirm: String) {
        if (_uiState.value == CreatePasswordUiState.Working) return
        when {
            password.length < IdentityStore.MIN_PASSWORD_BYTES ->
                _uiState.value = CreatePasswordUiState.Error("min_length")
            password != confirm ->
                _uiState.value = CreatePasswordUiState.Error("mismatch")
            else -> {
                _uiState.value = CreatePasswordUiState.Working
                viewModelScope.launch(Dispatchers.Default) {
                    val pw = password.toByteArray(Charsets.UTF_8)
                    try {
                        identityStore.createIdentity(pw)
                        _uiState.value = CreatePasswordUiState.Idle
                    } catch (e: IdentityExistsException) {
                        _uiState.value = CreatePasswordUiState.Error("exists")
                    } catch (e: Exception) {
                        _uiState.value = CreatePasswordUiState.Error("failed")
                    } finally {
                        pw.fill(0)
                    }
                }
            }
        }
    }
}

@HiltViewModel
class UnlockViewModel @Inject constructor(
    private val identityStore: IdentityStore,
    private val keystoreKekWrapper: KeystoreKekWrapper,
    private val biometricUnlock: BiometricUnlock
) : ViewModel() {

    private val _uiState = MutableStateFlow<UnlockUiState>(UnlockUiState.Idle)
    val uiState: StateFlow<UnlockUiState> = _uiState.asStateFlow()

    private val _biometricAvailable = MutableStateFlow(false)
    val biometricAvailable: StateFlow<Boolean> = _biometricAvailable.asStateFlow()

    fun refreshBiometricAvailability(activity: FragmentActivity) {
        viewModelScope.launch {
            val wrapped = identityStore.getRecord()?.wrappedKek
            _biometricAvailable.value = wrapped != null && biometricUnlock.canAuthenticate(activity)
        }
    }

    fun unlockWithPassword(password: String) {
        if (_uiState.value == UnlockUiState.Working) return
        _uiState.value = UnlockUiState.Working
        viewModelScope.launch(Dispatchers.Default) {
            val pw = password.toByteArray(Charsets.UTF_8)
            try {
                identityStore.unlockWithPassword(pw)
                _uiState.value = UnlockUiState.Idle
            } catch (e: WrongPasswordException) {
                _uiState.value = UnlockUiState.Error("wrong_password")
            } catch (e: Exception) {
                _uiState.value = UnlockUiState.Error("failed")
            } finally {
                pw.fill(0)
            }
        }
    }

    fun unlockBiometric(activity: FragmentActivity) {
        if (_uiState.value == UnlockUiState.Working) return
        _uiState.value = UnlockUiState.Working
        viewModelScope.launch(Dispatchers.Main) {
            try {
                val wrapped = identityStore.getRecord()?.wrappedKek
                if (wrapped == null) {
                    _uiState.value = UnlockUiState.Error("failed")
                    return@launch
                }
                val cipher = try {
                    keystoreKekWrapper.prepareUnwrapCipher(Base64Url.decode(wrapped.iv))
                } catch (e: KekWrapException) {
                    _uiState.value = UnlockUiState.Error("keystore_invalidated")
                    return@launch
                }
                when (val result = biometricUnlock.authenticate(
                    activity,
                    activity.getString(com.securetext.app.R.string.vault_biometric_title),
                    activity.getString(com.securetext.app.R.string.vault_biometric_subtitle),
                    cipher
                )) {
                    is BiometricResult.Success -> {
                        val kek = try {
                            keystoreKekWrapper.unwrap(result.cipher, Base64Url.decode(wrapped.ciphertext))
                        } catch (e: Exception) {
                            null
                        }
                        if (kek != null) {
                            withContext(Dispatchers.Default) { identityStore.unlockWithKek(kek) }
                            SecureWipe.wipe(kek)
                            _uiState.value = UnlockUiState.Idle
                        } else {
                            _uiState.value = UnlockUiState.Error("failed")
                        }
                    }
                    else -> _uiState.value = UnlockUiState.Idle
                }
            } catch (e: Exception) {
                _uiState.value = UnlockUiState.Error("failed")
            }
        }
    }
}
