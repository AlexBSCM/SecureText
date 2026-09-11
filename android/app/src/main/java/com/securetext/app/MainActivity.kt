package com.securetext.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import com.securetext.app.navigation.SecureTextAppRoot
import com.securetext.app.storage.IdentityStore
import com.securetext.app.ui.theme.SecureTextTheme
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    @Inject lateinit var identityStore: IdentityStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SecureTextTheme {
                SecureTextAppRoot()
            }
        }
    }

    override fun onStop() {
        super.onStop()
        identityStore.lock()
    }
}
