package org.visadahyu.datapavan

import android.content.pm.ApplicationInfo
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import org.visadahyu.datapavan.core.NativeCore
import org.visadahyu.datapavan.ui.DatapavanApp
import org.visadahyu.datapavan.ui.DatapavanTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val engineVersion = NativeCore.version()
        // Debug builds only: the end and length of the usage period, so that a cycle of Settings'
        // data-usage screen can be compared (scripts/compare-usage.sh). Release builds always read the
        // last 30 or 7 days up to now.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val usageUntil = intent.getLongExtra(EXTRA_USAGE_UNTIL, 0).takeIf { debuggable && it > 0 }
        val usageDays = intent.getIntExtra(EXTRA_USAGE_DAYS, 0).takeIf { debuggable && it > 0 }
        setContent {
            DatapavanTheme {
                DatapavanApp(engineVersion = engineVersion, usageUntil = usageUntil, usageDays = usageDays)
            }
        }
    }

    private companion object {
        const val EXTRA_USAGE_UNTIL = "usage_until"
        const val EXTRA_USAGE_DAYS = "usage_days"
    }
}
