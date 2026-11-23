package org.visadahyu.datapavan.ui

import androidx.compose.material3.LocalTextStyle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import org.visadahyu.datapavan.R
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
    // The language the strings shown are in, which Android chose from the phone's languages and this part's
    // translations; not the phone's first language, which may be one Datapavan has no strings in.
    val language = stringResource(R.string.text_language)
    androidx.compose.material3.Text(
        remember(text, language) { inAppLanguage(text, language) },
        modifier = modifier,
        color = color,
        fontFamily = fontFamily,
        style = style,
    )
}

/**
 * A text that is not in the app's language, left unmarked so that a screen reader reads it in the phone's: an app's
 * name on its own, a licence, a fingerprint.
 */
@Composable
internal fun TextAsIs(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Color.Unspecified,
    fontFamily: FontFamily? = null,
    style: TextStyle = LocalTextStyle.current,
) {
    androidx.compose.material3.Text(text, modifier = modifier, color = color, fontFamily = fontFamily, style = style)
}
