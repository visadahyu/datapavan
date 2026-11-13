package org.visadahyu.datapavan.ui

import android.app.Activity
import android.app.LocaleManager
import android.app.UiModeManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import androidx.core.net.toUri
import java.text.DateFormat
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeParseException
import java.util.Date
import java.util.Locale
import org.visadahyu.datapavan.BuildConfig
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.Release
import org.visadahyu.datapavan.safety.ScreenProtection

/** The appearance the user picked (ADR 0027, point 3). */
enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** The app's languages; [tag] is null for the system's. */
enum class AppLanguage(val tag: String?) {
    SYSTEM(null), ENGLISH("en"), FRENCH("fr"), GERMAN("de"), SPANISH("es"), RUSSIAN("ru"), CHINESE("zh-CN"), ARABIC("ar"), PERSIAN("fa")
}

/**
 * The settings, in app-private storage that backups exclude like all of Datapavan's data. The language
 * is stored here only before Android 13; later versions keep it as the system's per-app language.
 */
class AppPreferences(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var theme: ThemeMode
        get() = ThemeMode.entries.firstOrNull { it.name == prefs.getString(THEME, null) } ?: ThemeMode.SYSTEM
        set(value) = prefs.edit { putString(THEME, value.name) }

    var languageTag: String?
        get() = prefs.getString(LANGUAGE, null)
        set(value) = prefs.edit { if (value == null) remove(LANGUAGE) else putString(LANGUAGE, value) }

    private companion object {
        const val THEME = "theme"
        const val LANGUAGE = "language"
    }
}

/** Sets the language on every supported Android version (ADR 0027, point 3). */
object Languages {
    fun current(context: Context): AppLanguage {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.getSystemService(LocaleManager::class.java).applicationLocales.get(0)?.language
        } else {
            AppPreferences(context).languageTag
        }
        return AppLanguage.entries.firstOrNull { it.tag != null && it.tag == tag } ?: AppLanguage.SYSTEM
    }

    /** Android 13 and later recreate the activity themselves; before, it is recreated here. */
    fun set(activity: Activity, language: AppLanguage) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.getSystemService(LocaleManager::class.java).applicationLocales =
                language.tag?.let { LocaleList.forLanguageTags(it) } ?: LocaleList.getEmptyLocaleList()
        } else {
            AppPreferences(activity).languageTag = language.tag
            activity.recreate()
        }
    }

    /** Before Android 13: the activity's context in the chosen language, for attachBaseContext. */
    fun wrap(base: Context): Context {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return base
        val tag = AppPreferences(base).languageTag ?: return base
        val configuration = Configuration(base.resources.configuration).apply { setLocale(Locale.forLanguageTag(tag)) }
        return base.createConfigurationContext(configuration)
    }
}

/** Whether the app is dark, given the choice and the system's. */
internal fun ThemeMode.isDark(systemDark: Boolean) = when (this) {
    ThemeMode.SYSTEM -> systemDark
    ThemeMode.LIGHT -> false
    ThemeMode.DARK -> true
}

/** From Android 12 the system also knows the app's choice, so its own screens and bars follow it. */
internal fun applyNightMode(context: Context, mode: ThemeMode) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
    context.getSystemService(UiModeManager::class.java).setApplicationNightMode(
        when (mode) {
            ThemeMode.SYSTEM -> UiModeManager.MODE_NIGHT_AUTO
            ThemeMode.LIGHT -> UiModeManager.MODE_NIGHT_NO
            ThemeMode.DARK -> UiModeManager.MODE_NIGHT_YES
        },
    )
}

/** What the settings screen leads to. */
enum class SettingsPage { DATA_SOURCES, OWN_COPY, PRIVACY, LICENCES, ABOUT }

/** Settings (ADR 0027, point 3): appearance, language, and the pages about the app itself. */
@Composable
internal fun SettingsScreen(theme: ThemeMode, insets: PaddingValues, onTheme: (ThemeMode) -> Unit, onPage: (SettingsPage) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    val language = Languages.current(context)
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineSmall)
        }
        item {
            SectionTitle(R.string.settings_appearance)
            Choices(ThemeMode.entries, theme, { stringResource(themeName(it)) }, onTheme)
        }
        item {
            SectionTitle(R.string.settings_language)
            Choices(AppLanguage.entries, language, { languageName(it) }) { choice ->
                if (choice != language) (context as? Activity)?.let { Languages.set(it, choice) }
            }
        }
        item {
            SectionTitle(R.string.screenshots_title)
            ScreenshotSetting()
        }
        item { HorizontalDivider() }
        items(SettingsPage.entries) { page ->
            Text(
                stringResource(pageName(page)),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable { onPage(page) }.padding(vertical = 12.dp),
            )
        }
    }
}

@Composable
private fun <T> Choices(options: List<T>, selected: T, name: @Composable (T) -> String, onPick: (T) -> Unit) {
    Column(Modifier.selectableGroup()) {
        options.forEach { option ->
            Row(
                Modifier.fillMaxWidth().heightIn(min = 48.dp)
                    .selectable(selected = option == selected, onClick = { onPick(option) }, role = Role.RadioButton),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == selected, onClick = null)
                Text(name(option), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
            }
        }
    }
}

/** Each language in its own words, so that a user who cannot read the current one still finds theirs. */
@Composable
private fun languageName(language: AppLanguage): String = when (language) {
    AppLanguage.SYSTEM -> stringResource(R.string.settings_language_system)
    AppLanguage.ENGLISH -> isolate("English")
    AppLanguage.FRENCH -> isolate("Français")
    AppLanguage.GERMAN -> isolate("Deutsch")
    AppLanguage.SPANISH -> isolate("Español")
    AppLanguage.RUSSIAN -> isolate("Русский")
    AppLanguage.CHINESE -> isolate("简体中文")
    AppLanguage.ARABIC -> isolate("العربية")
    AppLanguage.PERSIAN -> isolate("فارسی")
}

@StringRes
private fun themeName(mode: ThemeMode) = when (mode) {
    ThemeMode.SYSTEM -> R.string.settings_theme_system
    ThemeMode.LIGHT -> R.string.settings_theme_light
    ThemeMode.DARK -> R.string.settings_theme_dark
}

@StringRes
private fun pageName(page: SettingsPage) = when (page) {
    SettingsPage.DATA_SOURCES -> R.string.data_sources_title
    SettingsPage.OWN_COPY -> R.string.own_title
    SettingsPage.PRIVACY -> R.string.privacy_title
    SettingsPage.LICENCES -> R.string.licences_title
    SettingsPage.ABOUT -> R.string.about_title
}

/** A page of plain text: the privacy summary, or about. */
@Composable
internal fun TextPage(@StringRes title: Int, paragraphs: List<String>, insets: PaddingValues, onBack: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(title), style = MaterialTheme.typography.headlineSmall)
        }
        items(paragraphs) { Text(it, style = MaterialTheme.typography.bodyLarge) }
    }
}

/**
 * About (ADR 0027, point 3): the version and its date, the licence and the source, then where newer
 * versions are. The addresses are plain text in a fixed direction, without bidi marks, so that a copy of
 * one works in a browser's address bar; the button opens the website's download section in the browser,
 * and Datapavan itself still connects to nothing.
 */
@Composable
internal fun AboutPage(engineVersion: String, insets: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    val locale = LocalConfiguration.current.locales[0]
    val paragraphs = aboutParagraphs(engineVersion)
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.about_title), style = MaterialTheme.typography.headlineSmall)
        }
        items(paragraphs) { Text(it, style = MaterialTheme.typography.bodyLarge) }
        // The editions (ADR 0045), in a few calm lines, with no prompt.
        item {
            Text(stringResource(R.string.about_editions_title), style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(
                    when {
                        BuildConfig.PLAY -> R.string.about_editions_play
                        BuildConfig.ADVANCED -> R.string.about_editions_advanced
                        else -> R.string.about_editions_basic
                    },
                ),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        item {
            // Google Play updates Lite, so Lite says nothing of newer versions and links the website's main page.
            if (!BuildConfig.PLAY) {
                Text(stringResource(R.string.about_updates_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.about_updates), style = MaterialTheme.typography.bodyLarge)
            }
            val address = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr)
            SelectionContainer {
                Column(Modifier.padding(vertical = 8.dp)) {
                    Text(Release.WEBSITE, style = address)
                    if (!BuildConfig.PLAY) Text(Release.RELEASES, style = address)
                }
            }
            Text(stringResource(R.string.about_copy_hint), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = {
                val page = if (BuildConfig.PLAY) Release.homePage(locale) else Release.downloadPage(locale)
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, page.toUri()))
                } catch (_: ActivityNotFoundException) {
                    // No browser: the addresses above can still be copied.
                }
            }) { Text(stringResource(R.string.about_open_website)) }
        }
    }
}

/** This version's release date in the user's format, as the network period shows dates. */
internal fun releaseDateText(): String = try {
    val day = LocalDate.parse(Release.date)
    DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date.from(day.atStartOfDay(ZoneId.systemDefault()).toInstant()))
} catch (_: DateTimeParseException) {
    Release.date
}

/**
 * The open-source components in the APK and their licences, as `cargo metadata` and the Gradle catalogue
 * name them; build-time crates such as proc macros are not shipped and not listed. Licence names stay
 * in English, as the licences do.
 */
private val COMPONENTS = listOf(
    "Datapavan" to "Apache-2.0",
    "Kotlin standard library" to "Apache-2.0",
    "AndroidX Activity, Lifecycle, Startup, Core" to "Apache-2.0",
    "Jetpack Compose (UI, Material 3)" to "Apache-2.0",
    "bytes" to "MIT",
    "cfg-if" to "MIT OR Apache-2.0",
    "combine" to "MIT",
    "ed25519-compact" to "MIT",
    "jni, jni-sys" to "MIT OR Apache-2.0",
    "log" to "MIT OR Apache-2.0",
    "memchr" to "Unlicense OR MIT",
    "simd_cesu8" to "Apache-2.0 OR MIT",
    "simdutf8" to "MIT OR Apache-2.0",
    "thiserror" to "MIT OR Apache-2.0",
)

@Composable
internal fun LicencesScreen(insets: PaddingValues, onBack: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.licences_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.licences_intro), style = MaterialTheme.typography.bodyMedium)
        }
        items(COMPONENTS) { (name, licence) ->
            SelectionContainer {
                Column {
                    Text(name, style = MaterialTheme.typography.titleSmall.copy(textDirection = TextDirection.Ltr))
                    Text(licence, style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

/**
 * Every screen blocks screenshots and screen recordings (ADR 0040). A person who needs a screenshot to ask
 * for help allows it here for one minute; it is blocked again then, or when the app leaves the screen.
 */
@Composable
private fun ScreenshotSetting() {
    val lifted by ScreenProtection.lifted.collectAsState()
    Text(
        stringResource(if (lifted) R.string.screenshots_allowed else R.string.screenshots_blocked),
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
    if (lifted) {
        OutlinedButton(onClick = ScreenProtection::protect) { Text(stringResource(R.string.screenshots_block)) }
    } else {
        OutlinedButton(onClick = ScreenProtection::lift) { Text(stringResource(R.string.screenshots_allow)) }
    }
}
