package com.securetext.app.navigation

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.People
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.ui.graphics.vector.ImageVector
import com.securetext.app.R

sealed class Destinations(val route: String, @StringRes val titleRes: Int, val icon: ImageVector) {
    data object Identity : Destinations("identity", R.string.nav_identity, Icons.Outlined.Key)
    data object Encrypt : Destinations("encrypt", R.string.nav_encrypt, Icons.Outlined.Lock)
    data object Decrypt : Destinations("decrypt", R.string.nav_decrypt, Icons.Outlined.LockOpen)
    data object Contacts : Destinations("contacts", R.string.nav_contacts, Icons.Outlined.People)
    data object Settings : Destinations("settings", R.string.nav_settings, Icons.Outlined.Settings)

    companion object {
        val all: List<Destinations> = listOf(Identity, Encrypt, Decrypt, Contacts, Settings)
    }
}
