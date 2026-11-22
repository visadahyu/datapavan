package org.visadahyu.datapavan.watch

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * The apps the user left out of Watch's tunnel (ADR 0041, decision 2): when an app does not work with
 * Watch, or refuses to run while a VPN is on, it goes to the internet directly. Android then does not
 * give it the VPN as its network, and Watch neither sees nor records its connections. Watch itself is
 * never left out: its engine needs it inside its own tunnel (ADR 0012).
 */
class LeftOut private constructor(private val prefs: SharedPreferences, private val self: String) {
    /** The packages left out, Watch's own never among them. */
    var apps: Set<String>
        get() = prefs.getStringSet(APPS, emptySet()).orEmpty() - self
        set(value) = prefs.edit { putStringSet(APPS, value - self) }

    companion object {
        private const val PREFS = "left_out"
        private const val APPS = "apps"

        fun of(context: Context) = LeftOut(
            context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE),
            context.packageName,
        )
    }
}
