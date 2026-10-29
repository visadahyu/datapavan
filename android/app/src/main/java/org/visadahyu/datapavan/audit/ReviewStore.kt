package org.visadahyu.datapavan.audit

import android.content.Context
import androidx.core.content.edit

/**
 * Remembers, in app-private storage, which sensor access the user had when they reviewed an app.
 * Nothing leaves the phone, and backups exclude this file like all of Datapavan's data.
 */
class ReviewStore(context: Context) {
    private val prefs = context.getSharedPreferences("sensor_review", Context.MODE_PRIVATE)

    fun all(): Map<String, Set<Sensor>> = prefs.all.mapNotNull { (pkg, value) ->
        (value as? String)?.let { pkg to decode(it) }
    }.toMap()

    fun markReviewed(packageName: String, sensors: Set<Sensor>) {
        prefs.edit { putString(packageName, sensors.joinToString(",") { it.name }) }
    }

    fun clear(packageName: String) {
        prefs.edit { remove(packageName) }
    }

    private fun decode(value: String): Set<Sensor> =
        value.split(',').mapNotNull { name -> Sensor.entries.firstOrNull { it.name == name } }.toSet()
}
