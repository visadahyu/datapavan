package org.visadahyu.datapavan.network

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.mutableStateOf
import org.visadahyu.datapavan.labels.PhoneLocales
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.network.chain.Tools
import org.visadahyu.datapavan.network.guides.GuideView
import org.visadahyu.datapavan.network.guides.Guides
import org.visadahyu.datapavan.network.guides.ToolLabels
import org.visadahyu.datapavan.network.ui.GuideScreen
import org.visadahyu.datapavan.network.ui.NetworkTheme

/**
 * One tool's guide for proxy mode (W8, part 3b; ADR 0041, "How the per-tool guides are built"), in Watch's process,
 * opened by a non-exported intent from the chain section's links, and in W9 from onboarding, with [EXTRA_GUIDE] and
 * the installed tool's [EXTRA_PACKAGE], whose own labels the guide quotes. The tool's labels are read off the main
 * thread; nothing of the tool runs. Protected from screenshots as every screen is (ADR 0040).
 */
class GuideActivity : ComponentActivity() {
    private val view = mutableStateOf<GuideView?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        val testBuild = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        ScreenProtection.attach(this, screenshotsForTests = testBuild && intent.getBooleanExtra(EXTRA_SCREENSHOTS, false))
        val id = intent.getStringExtra(EXTRA_GUIDE)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE)
        setContent { NetworkTheme { GuideScreen(view.value) } }
        Thread {
            val book = Guides.book(this)
            val guide = id?.let(book::guide) ?: packageName?.let(book::guideOf)
            if (guide == null) {
                runOnUiThread { finish() }
                return@Thread
            }
            val tool = packageName?.takeIf { it in guide.packages } ?: guide.packages.first()
            val name = Tools.table(this).firstOrNull { it.packageName == tool }?.name ?: tool
            val read = ToolLabels.reader(this, tool) ?: { _, _ -> null }
            // The phone's languages from LocaleManager from Android 13, where Resources.getSystem() follows
            // Datapavan's own language in its process (ADR 0054, the audit's M1).
            val labels = ToolLabels(book, guide, read, phone = PhoneLocales.of(this), own = PhoneLocales.own(this))
            val shown = GuideView.of(book, guide, name, labels) { first, second -> getString(R.string.label_with_own, first, second) }
            runOnUiThread { view.value = shown }
        }.apply { name = "network-guide" }.start()
    }

    companion object {
        const val EXTRA_GUIDE = "guide"
        const val EXTRA_PACKAGE = "package"

        /** Debug builds only, as on Watch's screen: screenshots allowed for a script. */
        const val EXTRA_SCREENSHOTS = "screenshots"

        fun intent(context: Context, guide: String, packageName: String?): Intent =
            Intent(context, GuideActivity::class.java).putExtra(EXTRA_GUIDE, guide).putExtra(EXTRA_PACKAGE, packageName)
    }
}
