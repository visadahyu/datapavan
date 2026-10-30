package org.visadahyu.datapavan.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.SignatureVerdict
import java.util.Locale

/**
 * Whose key signed this app, judged against the list of official certificates (ADR 0018). Only a
 * copy with positive evidence of modification is shown as a warning; an unknown key is shown as a
 * fact, with the fingerprint to compare. A disguised build's real name stays behind a tap, because
 * the disguise protects people whose phones are searched.
 */
@Composable
internal fun SignatureSection(verdict: SignatureVerdict) {
    val body = MaterialTheme.typography.bodyMedium
    Column {
        SectionTitle(R.string.signature_heading)
        when (verdict) {
            is SignatureVerdict.Genuine -> {
                val text = when (verdict.controller) {
                    "google" -> R.string.signature_genuine_google
                    "fdroid" -> R.string.signature_genuine_fdroid
                    else -> R.string.signature_genuine_developer
                }
                Text(stringResource(text, verdict.app), style = body)
                if (verdict.pastKeyOnly) Text(stringResource(R.string.signature_past_key), style = body)
            }
            is SignatureVerdict.UnknownKey -> {
                Text(stringResource(R.string.signature_unknown, verdict.app), style = body)
                Fingerprint(verdict.fingerprint)
            }
            is SignatureVerdict.Modified -> {
                val text = if (verdict.debugKey) R.string.signature_modified_debug else R.string.signature_modified
                Text(stringResource(text, verdict.app), style = body, color = MaterialTheme.colorScheme.error)
                Fingerprint(verdict.fingerprint)
            }
            is SignatureVerdict.Disguised -> {
                var shown by rememberSaveable { mutableStateOf(false) }
                if (shown) {
                    Text(stringResource(R.string.signature_disguised, verdict.app), style = body)
                } else {
                    TextButton(onClick = { shown = true }) { Text(stringResource(R.string.signature_disguised_hidden)) }
                }
            }
        }
    }
}

/** A SHA-256 fingerprint as developers usually print it: colon-separated uppercase pairs. */
@Composable
private fun Fingerprint(hex: String) {
    SelectionContainer {
        Text(
            hex.split(' ').joinToString("\n") { digest -> digest.uppercase(Locale.ROOT).chunked(2).joinToString(":") },
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
