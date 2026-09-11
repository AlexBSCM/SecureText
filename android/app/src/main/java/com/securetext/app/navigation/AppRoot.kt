package com.securetext.app.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.securetext.app.storage.IdentityStore
import com.securetext.app.storage.VaultState
import com.securetext.app.ui.vault.CreatePasswordScreen
import com.securetext.app.ui.vault.UnlockScreen
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.launch

@HiltViewModel
class VaultGateViewModel @Inject constructor(
    private val identityStore: IdentityStore
) : ViewModel() {
    val vaultState = identityStore.state

    init {
        viewModelScope.launch { identityStore.initialize() }
    }
}

@Composable
fun SecureTextAppRoot(vaultGateViewModel: VaultGateViewModel = hiltViewModel()) {
    val vaultState by vaultGateViewModel.vaultState.collectAsStateWithLifecycle()

    when (vaultState) {
        VaultState.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        VaultState.NoIdentity -> CreatePasswordScreen()
        VaultState.Locked -> UnlockScreen()
        VaultState.Unlocked -> SecureTextNavHost()
    }
}
