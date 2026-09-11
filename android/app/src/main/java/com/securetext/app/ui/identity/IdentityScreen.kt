package com.securetext.app.ui.identity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.securetext.app.R
import com.securetext.app.storage.IdentityStore
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class IdentityViewModel @Inject constructor(
    private val identityStore: IdentityStore
) : ViewModel() {
    suspend fun publicIdentity(): String = identityStore.publicIdentity()
    suspend fun fingerprint(): String = identityStore.fingerprint()
}

@Composable
fun IdentityScreen(viewModel: IdentityViewModel = hiltViewModel()) {
    val identity by produceState<String?>(initialValue = null) {
        value = try { viewModel.publicIdentity() } catch (_: Exception) { null }
    }
    val fingerprint by produceState<String?>(initialValue = null) {
        value = try { viewModel.fingerprint() } catch (_: Exception) { null }
    }
    val clipboard = LocalClipboardManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(stringResource(R.string.screen_identity_title), style = MaterialTheme.typography.headlineSmall)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    stringResource(R.string.identity_public_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    identity ?: stringResource(R.string.identity_loading),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    identity?.let { clipboard.setText(AnnotatedString(it)) }
                }) {
                    Text(stringResource(R.string.identity_copy))
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    stringResource(R.string.identity_fingerprint_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    fingerprint ?: stringResource(R.string.identity_loading),
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    fingerprint?.let { clipboard.setText(AnnotatedString(it)) }
                }) {
                    Text(stringResource(R.string.identity_copy))
                }
            }
        }
    }
}
