package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.proxy.LoggedApps
import org.visadahyu.datapavan.network.proxy.ProxyChoice
import org.visadahyu.datapavan.ui.isolateLtr

/**
 * What the screens know of the user's choice for one app, "Log where APP connects through a proxy" (the proxy record's
 * unit C, R3), read by "Now" off the main thread with each snapshot: whether the switch of every app is on
 * ([switchOn]); the app UIDs the hand-over gives the engine now ([chosen], `LoggedApps.chosen`, so that a row agrees
 * with the engine on an app installed again meanwhile); why each package's choice ended in this run ([ended]); the apps
 * whose choice the user ended on this screen ([stopped]), for the note of what stays; the circumvention tools and
 * Android's PAC handler by UID ([tools], [pacHandler]), as the service read them or, while the tunnel is off, the screen
 * itself; this user's number ([user]); and whether the SDK Runtime is on ([sdkRuntime]).
 */
internal data class ProxyChoices(
    val switchOn: Boolean = false,
    val chosen: Set<Int> = emptySet(),
    val ended: Map<String, LoggedApps.Ended> = emptyMap(),
    val stopped: Set<Int> = emptySet(),
    val tools: Set<Int> = emptySet(),
    val pacHandler: Int? = null,
    val user: Int = 0,
    val sdkRuntime: Boolean = false,
) {
    /** Whether the app of [uid] is chosen; an SDK Runtime UID's, its app's. */
    fun chosen(uid: Int?): Boolean = uid != null && ProxyChoice.appOf(uid) in chosen

    /** What a proxy row of [uid] can offer: through Android's setting ([setting]) or a [local] proxy, on a [tcp] flow. */
    fun row(uid: Int?, setting: Boolean, local: Boolean?, tcp: Boolean = true): RowChoice =
        RowChoice(ProxyChoice.offered(uid, tools, pacHandler, setting, local, user), chosen(uid), switchOn, tcp)

    /** Whether the app of [uid] can be chosen at all, on its page: an application of this user, no tool, no PAC handler. */
    fun offered(uid: Int?): Boolean = ProxyChoice.offered(uid, tools, pacHandler, setting = false, local = false, user = user)
}

/**
 * The taps on the choice: [onLog] once the confirmation said yes, [onStop] at once (a choice turned off keeps less, so
 * it asks nothing). Each takes the app's UID, an SDK Runtime UID's app already found.
 */
internal class ProxyChoiceActions(val onLog: (Int) -> Unit = {}, val onStop: (Int) -> Unit = {})

/**
 * The lines an app's row in "Now" and its page say of its choice, as a pure function the JVM tests hold: that the user
 * ended it on this screen, and what stays (audit-C 8); or why it ended without the user in this run (audit-C 13),
 * [packages] being the app's. Nothing while it is chosen.
 */
internal fun appChoiceLines(uid: Int?, packages: List<String>, choices: ProxyChoices): List<Int> {
    if (uid == null || choices.chosen(uid)) return emptyList()
    val lines = mutableListOf<Int>()
    if (ProxyChoice.appOf(uid) in choices.stopped) lines += R.string.proxy_app_stopped
    when (packages.firstNotNullOfOrNull { choices.ended[it] }) {
        LoggedApps.Ended.INSTALLED_AGAIN -> lines += R.string.proxy_app_ended_installed
        LoggedApps.Ended.SHARED -> lines += R.string.proxy_app_ended_shared
        LoggedApps.Ended.TOOL -> lines += R.string.proxy_app_ended_tool
        null -> Unit
    }
    return lines
}

/**
 * Whether an app's page draws the switch "Log where APP connects through a proxy" (C8; audit-C 25), as a pure function
 * the JVM tests hold: the choice can cover the app ([ProxyChoices.offered]), and it is chosen, the user ended it here, or
 * a proxy of the app was seen in "Now" or on any day read since the page opened ([proxiesSeen]), so that paging through
 * the days does not make it come and go.
 */
internal fun appSwitchShown(uid: Int?, choices: ProxyChoices, proxiesSeen: Boolean): Boolean =
    uid != null && choices.offered(uid) && (choices.chosen(uid) || ProxyChoice.appOf(uid) in choices.stopped || proxiesSeen)

/**
 * The switch on an app's page, drawn as the switch of every app is on its own (LogSwitchAlone): turning it on asks
 * first ([onAsk]), turning it off acts at once ([onStop]). Under it, while the switch of every app is on, that it logs
 * this app's proxy anyway; then [lines] ([appChoiceLines]).
 */
@Composable
internal fun AppProxySwitch(name: String, chosen: Boolean, switchOn: Boolean, lines: List<Int>, onAsk: () -> Unit, onStop: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = chosen, role = Role.Switch, onValueChange = { on -> if (on) onAsk() else onStop() })
                .padding(vertical = 4.dp)
                .testTag("proxy-app-log"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.proxy_app_log, name), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Switch(checked = chosen, onCheckedChange = null)
        }
        if (switchOn) Text(stringResource(R.string.proxy_app_log_switch_on), style = MaterialTheme.typography.bodyMedium)
        AppChoiceLines(lines)
    }
}

/** [appChoiceLines], one line each. */
@Composable
internal fun AppChoiceLines(lines: List<Int>) {
    for (line in lines) Text(stringResource(line), style = MaterialTheme.typography.bodyMedium)
}

/** A row's link to the choice ([Choice]), after the switch's link. */
@Composable
internal fun ChoiceLink(choice: Choice, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.testTag(if (choice == Choice.LOG) "proxy-app-log-link" else "proxy-app-stop-link")) {
        Text(stringResource(if (choice == Choice.LOG) R.string.proxy_app_log_link else R.string.proxy_app_stop_link))
    }
}

/**
 * The confirmation of the choice for the app [name] (C8, with audit-C 6 and 13): what it logs from now on, every
 * package of a shared UID ([packages]), the SDK Runtime where it is on ([sdkRuntime]), what it never covers, and what
 * ends it. Neither button is chosen beforehand, as the removal of a configuration asks (Tunnels.kt).
 */
@Composable
internal fun AppProxyChoiceDialog(name: String, packages: List<String>, sdkRuntime: Boolean, onYes: () -> Unit, onNo: () -> Unit) {
    AlertDialog(
        onDismissRequest = onNo,
        title = { Text(stringResource(R.string.proxy_app_log_title, name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.proxy_app_log_body, name), style = MaterialTheme.typography.bodyMedium)
                if (packages.size > 1) {
                    Text(
                        stringResource(R.string.proxy_app_log_together, packages.joinToString(", ") { isolateLtr(it) }),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (sdkRuntime) Text(stringResource(R.string.proxy_app_log_sdk), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.proxy_app_log_never), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.proxy_app_log_ends), style = MaterialTheme.typography.bodyMedium)
            }
        },
        confirmButton = {
            TextButton(onClick = onYes, modifier = Modifier.testTag("proxy-app-log-yes")) { Text(stringResource(R.string.proxy_app_log_yes)) }
        },
        dismissButton = {
            TextButton(onClick = onNo, modifier = Modifier.testTag("proxy-app-log-no")) { Text(stringResource(R.string.proxy_app_log_no)) }
        },
    )
}

/**
 * Whether the SDK Runtime is on, on Android 13 and later, where an app's SDKs can run under a UID of their own (audit-C
 * 21): it can be off on a phone, and Android deprecates it in 17.
 */
internal fun sdkRuntimeOn(): Boolean {
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) return false
    return try {
        @Suppress("DEPRECATION")
        android.app.sdksandbox.SdkSandboxManager.getSdkSandboxState() ==
            android.app.sdksandbox.SdkSandboxManager.SDK_SANDBOX_STATE_ENABLED_PROCESS_ISOLATION
    } catch (e: LinkageError) {
        false
    }
}
