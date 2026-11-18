package org.visadahyu.datapavan.ui

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.BuildConfig
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.SignatureVerdict
import java.util.Locale

/**
 * Whether this copy of Datapavan is genuine (ADR 0024): its own signing key, judged against its
 * own entry in `data/app-signers` like any other app, and whether it asks for what its edition never
 * asks for: the internet in Basic; the camera, microphone, location, contacts, messages or call log in
 * Advanced, which has the internet for its apps' traffic (ADR 0045, decision 4; review b2 of W5's second
 * part, fresh, M0: Advanced's genuine copy was told it was not). Both are a speed bump only, since a
 * forger controls this screen too; the screen says that the real check compares the key from outside.
 */
@Composable
internal fun OwnCopyScreen(signing: AppSigning?, verdict: SignatureVerdict?, insets: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    val refused = remember { asksForWhatItNever(requestedPermissions(context), neverRequested()) }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.own_title), style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Text(
                stringResource(if (BuildConfig.ADVANCED) R.string.own_teach_advanced else R.string.own_teach),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        item {
            val check = when {
                BuildConfig.ADVANCED && refused -> R.string.own_permissions_present_advanced
                BuildConfig.ADVANCED -> R.string.own_permissions_none_advanced
                refused -> R.string.own_internet_present
                else -> R.string.own_internet_none
            }
            Text(
                stringResource(check),
                style = MaterialTheme.typography.bodyMedium,
                color = if (refused) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
        }
        item {
            SectionTitle(R.string.own_key_label)
            SelectionContainer {
                Text(
                    signing?.current?.joinToString("\n") { fingerprint(it) } ?: stringResource(R.string.own_key_unknown),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr),
                )
            }
        }
        if (signing != null) item {
            Text(
                stringResource(
                    when {
                        signing.debug -> R.string.own_debug
                        verdict is SignatureVerdict.Genuine -> R.string.own_genuine
                        verdict is SignatureVerdict.Modified || verdict is SignatureVerdict.UnknownKey -> R.string.own_not_genuine
                        else -> R.string.own_no_record
                    },
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        item { Note(stringResource(R.string.own_updates)) }
        item { Note(stringResource(R.string.own_limit)) }
    }
}

/**
 * A certificate's SHA-256 as AppVerifier shows it, upper case in pairs separated by colons, with eight
 * pairs on each line so that no pair breaks.
 */
internal fun fingerprint(sha256: String): String =
    sha256.uppercase(Locale.ROOT).chunked(2).chunked(8).joinToString(":\n") { it.joinToString(":") }

/** What this edition never asks for, the build's own list: its build fails if anything adds one of them. */
internal fun neverRequested(): List<String> = BuildConfig.NEVER_REQUESTED.split(',').filter { it.isNotEmpty() }

/** Whether `requested`, the permissions a copy's manifest asks for, holds any of `never`. */
internal fun asksForWhatItNever(requested: Collection<String>, never: Collection<String>): Boolean =
    requested.any { it in never }

/** The permissions this copy's manifest asks for. */
private fun requestedPermissions(context: Context): List<String> {
    val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        context.packageManager.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
    } else {
        @Suppress("DEPRECATION")
        context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
    }
    return info.requestedPermissions?.toList().orEmpty()
}
