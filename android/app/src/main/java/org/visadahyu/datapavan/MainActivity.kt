package org.visadahyu.datapavan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import org.visadahyu.datapavan.core.NativeCore
import org.visadahyu.datapavan.ui.AppPreferences
import org.visadahyu.datapavan.ui.DatapavanApp
import org.visadahyu.datapavan.ui.DatapavanTheme
import org.visadahyu.datapavan.ui.Languages
import org.visadahyu.datapavan.ui.ThemeMode
import org.visadahyu.datapavan.ui.applyNightMode
import org.visadahyu.datapavan.ui.isDark

class MainActivity : ComponentActivity() {
    /** Before Android 13, the language chosen in the settings (ADR 0027). */
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(Languages.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val preferences = AppPreferences(this)
        edgeToEdge(preferences.theme)
        val engineVersion = NativeCore.version()
        // Debug builds only: the end and length of the usage period, so that a cycle of Settings'
        // data-usage screen can be compared (scripts/compare-usage.sh). Release builds always read the
        // last 30 or 7 days up to now.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val usageUntil = intent.getLongExtra(EXTRA_USAGE_UNTIL, 0).takeIf { debuggable && it > 0 }
        val usageDays = intent.getIntExtra(EXTRA_USAGE_DAYS, 0).takeIf { debuggable && it > 0 }
        setContent {
            var theme by remember { mutableStateOf(preferences.theme) }
            DatapavanTheme(theme) {
                DatapavanApp(
                    engineVersion = engineVersion, usageUntil = usageUntil, usageDays = usageDays, theme = theme,
                    onTheme = {
                        theme = it
                        preferences.theme = it
                        edgeToEdge(it)
                        applyNightMode(this, it)
                    },
                )
            }
        }
    }

    /** The system bars' icons in the colours of the chosen appearance. */
    private fun edgeToEdge(mode: ThemeMode) {
        val systemDark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (mode.isDark(systemDark)) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
    }

    private companion object {
        const val EXTRA_USAGE_UNTIL = "usage_until"
        const val EXTRA_USAGE_DAYS = "usage_days"
    }
}
