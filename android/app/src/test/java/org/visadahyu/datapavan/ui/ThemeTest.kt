package org.visadahyu.datapavan.ui

import androidx.compose.material3.ColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertTrue
import org.junit.Test

/** WCAG 2.2 contrast of the brand theme: 4.5:1 for text (AA), 3:1 for outlines and other non-text parts. */
class ThemeTest {
    private fun ratio(a: Color, b: Color): Double {
        val (light, dark) = listOf(a.luminance().toDouble(), b.luminance().toDouble()).sortedDescending()
        return (light + 0.05) / (dark + 0.05)
    }

    private fun check(name: String, s: ColorScheme) {
        val grounds = mapOf(
            "background" to s.background, "surface" to s.surface, "surfaceVariant" to s.surfaceVariant,
            "surfaceContainerLowest" to s.surfaceContainerLowest, "surfaceContainerLow" to s.surfaceContainerLow,
            "surfaceContainer" to s.surfaceContainer, "surfaceContainerHigh" to s.surfaceContainerHigh,
            "surfaceContainerHighest" to s.surfaceContainerHighest,
        )
        // Text the app draws on any surface, including the severity colours of findings.
        val texts = mapOf("onSurface" to s.onSurface, "onSurfaceVariant" to s.onSurfaceVariant, "primary" to s.primary, "tertiary" to s.tertiary, "error" to s.error)
        for ((t, text) in texts) for ((g, ground) in grounds) {
            assertTrue("$name: $t on $g is ${ratio(text, ground)}", ratio(text, ground) >= 4.5)
        }
        val pairs = listOf(
            "onPrimary" to (s.onPrimary to s.primary), "onPrimaryContainer" to (s.onPrimaryContainer to s.primaryContainer),
            "onSecondary" to (s.onSecondary to s.secondary), "onSecondaryContainer" to (s.onSecondaryContainer to s.secondaryContainer),
            "onTertiary" to (s.onTertiary to s.tertiary), "onTertiaryContainer" to (s.onTertiaryContainer to s.tertiaryContainer),
            "onError" to (s.onError to s.error), "onErrorContainer" to (s.onErrorContainer to s.errorContainer),
        )
        for ((p, colours) in pairs) assertTrue("$name: $p is ${ratio(colours.first, colours.second)}", ratio(colours.first, colours.second) >= 4.5)
        for ((g, ground) in grounds) assertTrue("$name: outline on $g is ${ratio(s.outline, ground)}", ratio(s.outline, ground) >= 3.0)
    }

    @Test
    fun theLightThemeMeetsWcagAa() = check("light", LightColors)

    @Test
    fun theDarkThemeMeetsWcagAa() = check("dark", DarkColors)
}
