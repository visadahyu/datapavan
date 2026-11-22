package org.visadahyu.datapavan.labels

import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Android's own labels, read from the phone (ADR 0054), against a phone played by maps of resources. */
class SystemLabelsTest {
    private fun locale(tag: String): Locale = Locale.forLanguageTag(tag)

    private val english = listOf(locale("en-US"))
    private val persian = listOf(locale("fa-IR"))

    private fun row(key: String, maker: String = "aosp", apis: IntRange = 29..Int.MAX_VALUE, pkg: String? = SETTINGS, handler: String? = null, name: String, verified: String? = null) =
        LabelRow(key, maker, apis, pkg, handler, "string", name, verified)

    /** Resources by package, name and language, as a phone holds them; the default words are English. */
    private class Phone(val strings: Map<Pair<String, String>, Map<String, String>>) {
        var reads = 0
        fun read(pkg: String, type: String, name: String, locales: List<Locale>): String? {
            reads++
            val texts = strings[pkg to name] ?: return null
            return locales.firstNotNullOfOrNull { texts[it.toLanguageTag()] ?: texts[it.language] } ?: texts["en"]
        }
    }

    private val settings = Phone(
        mapOf(
            (SETTINGS to "usage_access") to mapOf("en" to "Usage access", "fa" to "دسترسی به داده‌های مصرف", "zh" to "使用情况访问权限", "zh-TW" to "使用情況存取權"),
            (SETTINGS to "select_private_dns_configuration_title") to mapOf("en" to "Private DNS", "fa" to "‏DNS خصوصی"),
            (SETTINGS to "samsung_usage") to mapOf("en" to "Usage data access"),
            (SETTINGS to "blank") to mapOf("en" to " "),
            (SETTINGS to "placeholder") to mapOf("en" to "placeholder"),
            (SETTINGS to "format") to mapOf("en" to "%1\$s apps"),
            (CONTROLLER to "auto_revoke_label") to mapOf("en" to "Remove permissions if app isn’t used"),
        ),
    )

    private val fallbacks = mapOf(
        "usage_access" to mapOf("en" to "Usage access", "fa" to "دسترسی به داده‌های مصرف", "zh" to "使用情况访问权限"),
        "private_dns" to mapOf("en" to "Private DNS", "fa" to "DNS خصوصی"),
    )

    private fun labels(
        rows: List<LabelRow>,
        phone: List<Locale> = english,
        own: List<Locale> = english,
        maker: String = "google",
        sdk: Int = 35,
        handlers: Map<String, String> = emptyMap(),
        from: Phone = settings,
    ) = SystemLabels(
        { rows }, maker, sdk, phone, own, from::read, { handlers[it] },
        { key, at -> fallbacks[key]?.let { texts -> texts[(at ?: own.first()).language] } },
    )

    @Test
    fun aLabelIsReadFromThePhoneInItsLanguageWithDatapavansBeside() {
        val rows = listOf(row("usage_access", name = "usage_access"))
        assertEquals(SystemLabel("Usage access", english[0], null, english[0], LabelSource.PHONE, rows[0]), labels(rows).label("usage_access"))
        // An English phone with Datapavan in Persian: the phone's words, then Datapavan's language beside them.
        val both = labels(rows, phone = english, own = persian).label("usage_access")
        assertEquals("Usage access", both.text)
        assertEquals("دسترسی به داده‌های مصرف", both.also)
        // Both in one language: nothing beside it.
        assertNull(labels(rows, phone = persian, own = listOf(locale("fa"))).label("usage_access").also)
    }

    @Test
    fun aMakersRowsComeFirstAndTheAospRowsAfter() {
        val rows = listOf(
            row("usage_access", name = "usage_access"),
            row("usage_access", maker = "samsung", name = "samsung_usage", verified = "SM-A405FN A405FNXXU4CVA1"),
        )
        val samsung = labels(rows, maker = "samsung").label("usage_access")
        assertEquals("Usage data access", samsung.text)
        assertEquals(LabelSource.PHONE, samsung.source)
        // Another maker gets AOSP's name, read from its own Settings.
        assertEquals("Usage access", labels(rows, maker = "xiaomi").label("usage_access").text)
    }

    @Test
    fun anAospNameOnAMakerWithRowsForOtherLabelsIsAndroidsName() {
        val rows = listOf(
            row("usage_access", name = "usage_access"),
            row("private_dns", name = "select_private_dns_configuration_title"),
            row("private_dns", maker = "samsung", name = "select_private_dns_configuration_title", verified = "SM-A405FN A405FNXXU4CVA1"),
        )
        val samsung = labels(rows, maker = "samsung")
        // Its row for Private DNS says that its screen uses AOSP's name: this phone's label.
        assertEquals(LabelSource.PHONE, samsung.label("private_dns").source)
        // It has no row for usage access: AOSP's name as its Settings hold it, which its screen may not show.
        assertEquals(LabelSource.ANDROID, samsung.label("usage_access").source)
        assertTrue(samsung.anyAndroids(listOf("private_dns", "usage_access")))
        assertFalse(samsung.anyAndroids(listOf("private_dns")))
        // A maker with no rows at all is taken as AOSP's.
        assertEquals(LabelSource.PHONE, labels(rows, maker = "google").label("usage_access").source)
    }

    @Test
    fun aRowOutsideItsAndroidVersionsIsNotTried() {
        val rows = listOf(
            row("unused_app_setting", apis = 30..30, pkg = null, handler = "android.intent.action.AUTO_REVOKE_PERMISSIONS", name = "auto_revoke_label"),
            row("unused_app_setting", apis = 31..Int.MAX_VALUE, name = "usage_access"),
        )
        val handlers = mapOf("android.intent.action.AUTO_REVOKE_PERMISSIONS" to CONTROLLER)
        assertEquals("Remove permissions if app isn’t used", labels(rows, sdk = 30, handlers = handlers).label("unused_app_setting").text)
        assertEquals("Usage access", labels(rows, sdk = 33, handlers = handlers).label("unused_app_setting").text)
        // A handler that is no system app, or none: the row is skipped.
        assertEquals(LabelSource.FALLBACK, labels(rows, sdk = 30).label("unused_app_setting").source)
    }

    @Test
    fun aMissingPackageResourceOrUnusableTextGoesOnToTheNextPlace() {
        val rows = listOf(
            row("usage_access", pkg = "com.example.gone", name = "usage_access"),
            row("usage_access", name = "missing"),
            row("usage_access", name = "blank"),
            row("usage_access", name = "placeholder"),
            row("usage_access", name = "format"),
            row("usage_access", name = "usage_access"),
        )
        val label = labels(rows).label("usage_access")
        assertEquals("Usage access", label.text)
        assertEquals("usage_access", label.row?.name)
        assertEquals(LabelSource.PHONE, label.source)
    }

    @Test
    fun withNoPlaceTheFallbackIsInThePhonesLanguageWhereDatapavanHasIt() {
        val none = listOf(row("usage_access", name = "missing"))
        // A Persian phone, Datapavan in English (the Galaxy A56 the other way round): Persian, with English beside it.
        val persianPhone = labels(none, phone = persian, own = english).label("usage_access")
        assertEquals(SystemLabel("دسترسی به داده‌های مصرف", persian[0], "Usage access", english[0], LabelSource.FALLBACK), persianPhone)
        // A Turkish phone: Datapavan has no Turkish, so its own language alone.
        assertEquals(SystemLabel("Usage access", english[0], null, null, LabelSource.FALLBACK), labels(none, phone = listOf(locale("tr-TR"))).label("usage_access"))
        // Traditional Chinese is not Datapavan's Simplified: its own language alone.
        assertEquals("Usage access", labels(none, phone = listOf(locale("zh-TW"))).label("usage_access").text)
        assertEquals("使用情况访问权限", labels(none, phone = listOf(locale("zh-CN"))).label("usage_access").text)
        // No rows at all, as with a data pack that lacks the dataset.
        assertEquals("Usage access", labels(emptyList()).label("usage_access").text)
    }

    @Test
    fun alsoShowsWhereTheScriptsDifferToo() {
        val rows = listOf(row("usage_access", name = "usage_access"))
        assertTrue(OtherAppResources.sameWords(locale("zh-CN"), locale("zh-Hans-SG")))
        assertFalse(OtherAppResources.sameWords(locale("zh-TW"), locale("zh-CN")))
        assertFalse(OtherAppResources.sameWords(locale("zh-Hant"), locale("zh")))
        // A phone in Traditional Chinese with Datapavan in Simplified: both, as the two scripts differ.
        val label = labels(rows, phone = listOf(locale("zh-TW")), own = listOf(locale("zh-CN"))).label("usage_access")
        assertEquals("使用情況存取權", label.text)
        assertEquals("使用情况访问权限", label.also)
    }

    @Test
    fun eachLabelIsReadOnce() {
        val phone = Phone(settings.strings)
        val rows = listOf(row("usage_access", name = "usage_access"))
        val labels = labels(rows, phone = english, own = persian, from = phone)
        labels.label("usage_access")
        val reads = phone.reads
        labels.label("usage_access")
        labels.label("usage_access")
        assertEquals(reads, phone.reads)
    }

    @Test
    fun aRightToLeftLabelThatBeginsWithALatinWordKeepsItsDirection() {
        val rows = listOf(row("private_dns", name = "select_private_dns_configuration_title"))
        // AOSP's Persian begins with a right-to-left mark, which cleaning drops; the isolate is the language's.
        val label = labels(rows, phone = persian, own = english).label("private_dns")
        assertEquals("DNS خصوصی", label.text)
        val quoted = label.quoted { first, second -> "$first ($second)" }
        assertEquals("⁧DNS خصوصی⁩ (⁦Private DNS⁩)", quoted)
        // Alone, one language, as an English button: left to right.
        assertEquals("⁦Usage access⁩", labels(listOf(row("usage_access", name = "usage_access"))).label("usage_access").quoted { a, b -> "$a $b" })
    }

    @Test
    fun theRowsParseAsTheDataCheckReadsThem() {
        val text = """
            # comment
            usage_access	aosp	29-	com.android.settings	string	usage_access	-	aosp:settings@android-10.0.0_r47..android-17.0.0_r1
            unused_app_setting	aosp	30-30	handler:android.intent.action.AUTO_REVOKE_PERMISSIONS	string	auto_revoke_label	-	aosp:permissioncontroller@android-11.0.0_r48..android-11.0.0_r48
            usage_access	samsung	30-35	com.android.settings	string	samsung_usage	SM-A405FN A405FNXXU4CVA1	device
            broken	aosp	29	com.android.settings	string	x	-	device
            broken	aosp	29-	com.android.settings	array	x	-	device
            short	aosp	29-
        """.trimIndent()
        val rows = LabelRow.parse(text)
        assertEquals(3, rows.size)
        assertEquals(29..Int.MAX_VALUE, rows[0].apis)
        assertEquals("android.intent.action.AUTO_REVOKE_PERMISSIONS", rows[1].handler)
        assertNull(rows[1].packageName)
        assertEquals(30..35, rows[2].apis)
        assertEquals("SM-A405FN A405FNXXU4CVA1", rows[2].verified)
        assertNull(rows[0].verified)
    }

    /** The bundled dataset itself: every row of it parses, as the data check holds it. */
    @Test
    fun theBundledRowsAllParse() {
        val text = File("../../data/android-labels/labels.tsv").readText()
        val lines = text.lines().count { it.isNotBlank() && !it.startsWith("#") }
        val rows = LabelRow.parse(text)
        assertEquals(lines, rows.size)
        assertTrue(rows.all { it.maker == SystemLabels.AOSP || it.verified != null })
    }

    @Test
    fun aLabelIsCleanedBeforeItIsQuoted() {
        assertEquals("Proxy only", OtherAppResources.clean(" Proxy\n only‮⁦ "))
        // AOSP's German screen lock carries soft hyphens and a zero-width space; Persian keeps its zero-width non-joiner.
        assertEquals("Displaysperre", OtherAppResources.clean("Dis­play­sper­re"))
        assertEquals("App-Benachrichtigungen", OtherAppResources.clean("App-​Benachrichtigungen"))
        assertEquals("دسترس‌پذیری", OtherAppResources.clean("دسترس‌پذیری"))
        val long = OtherAppResources.clean("x".repeat(200))
        assertEquals(OtherAppResources.MAX, long.length)
        assertTrue(long.endsWith("…"))
    }

    private companion object {
        const val SETTINGS = "com.android.settings"
        const val CONTROLLER = "com.google.android.permissioncontroller"
    }
}
