package org.visadahyu.datapavan.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.Sdk
import org.visadahyu.datapavan.audit.SdkCapability
import org.visadahyu.datapavan.audit.SdkCategory

/**
 * SDKs that can share the phone's connection, give remote support or record the screen (ADR 0019).
 * Each finding states what was found, what the code does when it is on, what Datapavan could not
 * check, and the evidence; it never judges intent or consent, which differ from app to app.
 */
@Composable
internal fun SdkSection(sdks: List<Sdk>, accessibilityOn: Boolean) {
    Column {
        SectionTitle(R.string.sdks_heading)
        sdks.forEach { sdk ->
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.sdk_name, sdk.name, sdk.vendor), style = MaterialTheme.typography.titleSmall)
            when (sdk.category) {
                SdkCategory.TRAFFIC_SHARING -> TrafficSharing(sdk)
                SdkCategory.REMOTE_SUPPORT -> RemoteSupport(sdk, accessibilityOn)
                SdkCategory.SCREEN_RECORDING -> ScreenRecording(sdk)
            }
            Text(
                stringResource(R.string.sdk_evidence, isolateLtr(sdk.checked), sdk.vendor),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TrafficSharing(sdk: Sdk) {
    Line(stringResource(R.string.sdk_traffic_sharing))
    Line(stringResource(R.string.sdk_traffic_sharing_not_checked))
    Line(stringResource(R.string.sdk_traffic_sharing_vendor, sdk.vendor))
    sdk.settingsLabel?.let { Line(stringResource(R.string.sdk_settings_label, it)) }
    Line(stringResource(R.string.sdk_play_policy))
}

@Composable
private fun RemoteSupport(sdk: Sdk, accessibilityOn: Boolean) {
    Line(stringResource(R.string.sdk_remote_support))
    sdk.capabilities.mapNotNull(::capability).forEach { Line("• " + stringResource(it)) }
    if (accessibilityOn && SdkCapability.DEVICE_CONTROL in sdk.capabilities) {
        Text(stringResource(R.string.sdk_accessibility_on), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
    }
    Line(stringResource(R.string.sdk_remote_support_not_checked))
}

@Composable
private fun ScreenRecording(sdk: Sdk) {
    Line(stringResource(R.string.sdk_screen_recording, sdk.vendor))
    if (SdkCapability.LIVE in sdk.capabilities) Line(stringResource(R.string.sdk_screen_recording_live))
    Line(stringResource(R.string.sdk_screen_recording_not_checked))
}

@Composable
private fun Line(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(bottom = 4.dp))
}

@StringRes
private fun capability(capability: SdkCapability): Int? = when (capability) {
    SdkCapability.APP_SCREEN -> R.string.sdk_capability_app_screen
    SdkCapability.WHOLE_SCREEN -> R.string.sdk_capability_whole_screen
    SdkCapability.APP_CONTROL -> R.string.sdk_capability_app_control
    SdkCapability.DEVICE_CONTROL -> R.string.sdk_capability_device_control
    SdkCapability.FILES -> R.string.sdk_capability_files
    SdkCapability.LIVE -> null
}
