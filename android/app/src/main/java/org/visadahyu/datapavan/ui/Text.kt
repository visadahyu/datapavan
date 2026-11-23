package org.visadahyu.datapavan.ui

import androidx.compose.material3.LocalTextStyle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import org.visadahyu.datapavan.text.inAppLanguage

/**
 * Every text of this part of the app, marked as written in the app's own language, so that TalkBack reads it with that
 * language's voice when the phone speaks another; placeholders between isolates keep the phone's (inAppLanguage, the
 * accessibility unit's part 2). The same parameters as the calls here use; Material's own Text does the rest.
 */
@Composable
internal fun Text(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Color.Unspecified,
    fontFamily: FontFamily? = null,
    style: TextStyle = LocalTextStyle.current,
) {
    val language = LocalConfiguration.current.locales[0].toLanguageTag()
    androidx.compose.material3.Text(
        remember(text, language) { inAppLanguage(text, language) },
        modifier = modifier,
        color = color,
        fontFamily = fontFamily,
        style = style,
    )
}
