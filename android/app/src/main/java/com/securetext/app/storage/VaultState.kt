package com.securetext.app.storage

sealed interface VaultState {
    data object Loading : VaultState
    data object NoIdentity : VaultState
    data object Locked : VaultState
    data object Unlocked : VaultState
}
