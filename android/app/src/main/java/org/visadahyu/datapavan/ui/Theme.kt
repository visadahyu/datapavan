package org.visadahyu.datapavan.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * The brand's colours (brand/README.md): lapis and clay in light mode, light lapis and night in dark
 * mode, gold for what needs a second colour. Datapavan does not take its colours from the wallpaper,
 * so that every pair of text and background keeps the contrast that ThemeTest measures, and a finding's
 * colour means the same on every phone.
 */
internal val LightColors: ColorScheme = lightColorScheme(
    primary = Color(0xFF1F4E8C),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD7E3F8),
    onPrimaryContainer = Color(0xFF0E2A4F),
    secondary = Color(0xFF4E5D72),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDCE3EE),
    onSecondaryContainer = Color(0xFF172131),
    // Darker than the palette's dark gold, which falls below 4.5:1 on cards.
    tertiary = Color(0xFF7A5212),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFF5DDB0),
    onTertiaryContainer = Color(0xFF2B1C00),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
    background = Color(0xFFFBF7F0),
    onBackground = Color(0xFF1D1B17),
    surface = Color(0xFFFBF7F0),
    onSurface = Color(0xFF1D1B17),
    surfaceVariant = Color(0xFFE8DFCE),
    onSurfaceVariant = Color(0xFF4A4436),
    outline = Color(0xFF7B7364),
    outlineVariant = Color(0xFFCEC5B3),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF7F1E7),
    surfaceContainer = Color(0xFFF3EBDC),
    surfaceContainerHigh = Color(0xFFEDE5D5),
    surfaceContainerHighest = Color(0xFFE8DFCE),
)

internal val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFF8DB0E6),
    onPrimary = Color(0xFF0B2547),
    primaryContainer = Color(0xFF1F4E8C),
    onPrimaryContainer = Color(0xFFD7E3F8),
    secondary = Color(0xFFB8C6DC),
    onSecondary = Color(0xFF223042),
    secondaryContainer = Color(0xFF394759),
    onSecondaryContainer = Color(0xFFD6E1F2),
    tertiary = Color(0xFFD9A54A),
    onTertiary = Color(0xFF3D2A00),
    tertiaryContainer = Color(0xFF5A3F05),
    onTertiaryContainer = Color(0xFFF5DDB0),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFF9DEDC),
    background = Color(0xFF14161C),
    onBackground = Color(0xFFE4E2DC),
    surface = Color(0xFF14161C),
    onSurface = Color(0xFFE4E2DC),
    surfaceVariant = Color(0xFF353841),
    onSurfaceVariant = Color(0xFFC4C6D0),
    outline = Color(0xFF8E909A),
    outlineVariant = Color(0xFF44474F),
    surfaceContainerLowest = Color(0xFF0F1116),
    surfaceContainerLow = Color(0xFF1B1D23),
    surfaceContainer = Color(0xFF1F2128),
    surfaceContainerHigh = Color(0xFF2A2C33),
    surfaceContainerHighest = Color(0xFF35373E),
)

@Composable
internal fun DatapavanTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}
