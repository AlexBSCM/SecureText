package com.securetext.app.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.securetext.app.ui.contacts.ContactsScreen
import com.securetext.app.ui.decrypt.DecryptScreen
import com.securetext.app.ui.encrypt.EncryptScreen
import com.securetext.app.ui.identity.IdentityScreen
import com.securetext.app.ui.settings.SettingsScreen

@Composable
fun SecureTextNavHost() {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: Destinations.Encrypt.route

    Scaffold(
        bottomBar = {
            NavigationBar {
                Destinations.all.forEach { dest ->
                    NavigationBarItem(
                        selected = currentRoute == dest.route,
                        onClick = {
                            navController.navigate(dest.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(dest.icon, contentDescription = null) },
                        label = { Text(stringResource(dest.titleRes)) },
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Destinations.Encrypt.route,
            modifier = Modifier.padding(padding),
        ) {
            composable(Destinations.Identity.route) { IdentityScreen() }
            composable(Destinations.Encrypt.route)  { EncryptScreen() }
            composable(Destinations.Decrypt.route)  { DecryptScreen() }
            composable(Destinations.Contacts.route) { ContactsScreen() }
            composable(Destinations.Settings.route) { SettingsScreen() }
        }
    }
}
