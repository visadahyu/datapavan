package org.visadahyu.datapavan.ui

import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.os.Build
import java.util.Locale

/**
 * Data sizes as the phone's own data-usage screen shows them, so that the numbers can be compared
 * with it (ADR 0022): the next unit once a value passes 900, and two decimals below 100, under the
 * usual unit names. The step differs by vendor. AOSP's Settings, as on the Android 17 emulator, steps
 * by 1,024; Samsung's, as on the A40, by 1,000. Other vendors are assumed to follow AOSP until a phone
 * of theirs is measured (scripts/compare-usage.sh).
 */
internal object DataSize {
    const val AOSP_STEP = 1024.0
    const val SI_STEP = 1000.0

    /** A size as a value in one unit: 0 bytes, 1 kB, 2 MB, 3 GB, 4 TB; with [decimals] digits. */
    data class Parts(val value: Double, val unit: Int, val decimals: Int)

    fun parts(bytes: Long, step: Double): Parts {
        var value = bytes.toDouble()
        var unit = 0
        while (value > NEXT_UNIT && unit < LAST_UNIT) {
            value /= step
            unit++
        }
        val decimals = if (unit == 0 || value >= 100) 0 else 2
        return Parts(value, unit, decimals)
    }

    fun format(bytes: Long, locale: Locale = Locale.getDefault()): String {
        val (value, unit, decimals) = parts(bytes, step())
        val number = NumberFormat.getInstance(locale).apply {
            minimumFractionDigits = decimals
            maximumFractionDigits = decimals
        }
        return MeasureFormat.getInstance(locale, MeasureFormat.FormatWidth.SHORT, number).format(Measure(value, units()[unit]))
    }

    private fun step() = if (Build.MANUFACTURER.equals("samsung", ignoreCase = true)) SI_STEP else AOSP_STEP

    private const val NEXT_UNIT = 900.0

    // Terabytes are the largest: petabytes need Android 11.
    private const val LAST_UNIT = 4

    // Built on use, so that [parts] runs in unit tests, where Android's ICU classes are stubs.
    private fun units() = listOf(MeasureUnit.BYTE, MeasureUnit.KILOBYTE, MeasureUnit.MEGABYTE, MeasureUnit.GIGABYTE, MeasureUnit.TERABYTE)
}
