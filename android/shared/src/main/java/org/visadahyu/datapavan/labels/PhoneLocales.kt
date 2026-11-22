package org.visadahyu.datapavan.labels

import android.app.LocaleManager
import android.content.Context
import android.content.res.Resources
import android.os.Build
import android.os.LocaleList
import java.util.Locale

/**
 * The phone's own languages, which its Settings and other apps follow, as against the one the user chose for
 * Datapavan. From Android 13 an app's own language also changes what `Resources.getSystem()` reports in its process
 * (seen on the Android 17 emulator), so the phone's are asked from LocaleManager; before, Datapavan sets its language
 * only in its activity's context, and `Resources.getSystem()` keeps the phone's (ADR 0054, the audit's M1).
 */
object PhoneLocales {
    fun of(context: Context): List<Locale> = choose(
        Build.VERSION.SDK_INT,
        system = {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) context.getSystemService(LocaleManager::class.java)?.systemLocales?.let(::list) else null
        },
        resources = { list(Resources.getSystem().configuration.locales) },
    )

    /** Datapavan's own languages, those of its resources in [context]. */
    fun own(context: Context): List<Locale> = list(context.resources.configuration.locales)

    /** The phone's languages on Android [sdk]: LocaleManager's [system] ones from 13 on, else those of [resources]. */
    fun choose(sdk: Int, system: () -> List<Locale>?, resources: () -> List<Locale>): List<Locale> {
        val asked = if (sdk >= Build.VERSION_CODES.TIRAMISU) system()?.takeIf { it.isNotEmpty() } else null
        return asked ?: resources()
    }

    fun list(locales: LocaleList): List<Locale> = (0 until locales.size()).map { locales[it] }
}
