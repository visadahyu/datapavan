package org.visadahyu.datapavan.labels

import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Android's own labels, read from the phone (ADR 0054), against a phone played by maps of resources. */
class SystemLabelsTest {
    private fun locale(tag: String): Locale = Locale.forLanguageTag(tag)

    private val english = listOf(locale("en-US"))
    private val persian = listOf(locale("fa-IR"))

    private fun row(key: String, maker: String = "aosp", apis: IntRange = 29..Int.MAX_VALUE, pkg: String = SETTINGS, name: String, verified: String? = null) =
        LabelRow(key, maker, apis, pkg, "string", name, verified)

    /** Resources by package, name and language tag or language, as a phone holds them; the default words are English. */
    private class Phone(val strings: Map<Pair<String, String>, Map<String, String>>, val failing: Set<String> = emptySet()) {
        var reads = 0
        fun read(pkg: String, type: String, name: String, locales: List<Locale>): String? {
            reads++
            if (pkg in failing) throw IllegalStateException("a resource of another app that fails to read")
            val texts = strings[pkg to name] ?: return null
            return locales.firstNotNullOfOrNull { texts[it.toLanguageTag()] ?: texts[it.language] } ?: texts["en"]
        }
    }

    private val settings = Phone(
        mapOf(
            (SETTINGS to "usage_access") to mapOf("en" to "Usage access", "fa" to "دسترسی به داده‌های مصرف", "zh" to "使用情况访问权限", "zh-TW" to "使用情況存取權"),
            (SETTINGS to "select_private_dns_configuration_title") to mapOf("en" to "Private DNS", "fa" to "‏DNS خصوصی"),
            (SETTINGS to "samsung_usage") to mapOf("en" to "Usage data access"),
            // Samsung's British default English, and its American English (the Galaxy A40, 2026-11-22).
            (SETTINGS to "high_power_apps") to mapOf("en" to "Optimise battery usage", "en-US" to "Optimize battery usage", "fa" to "بهینه‌سازی مصرف باتری"),
            // "VPN" is the same in English and Persian.
            (SETTINGS to "vpn_settings_title") to mapOf("en" to "VPN", "fa" to "VPN"),
            // A label the phone has in Persian only: Datapavan's English is then its own copy.
            (SETTINGS to "only_persian") to mapOf("fa" to "فقط فارسی"),
            (SETTINGS to "blank") to mapOf("en" to " "),
            (SETTINGS to "placeholder") to mapOf("en" to "placeholder"),
            (SETTINGS to "format") to mapOf("en" to "%1\$s apps"),
            (CONTROLLER to "auto_revoke_label") to mapOf("en" to "Remove permissions if app isn’t used"),
            (AOSP_CONTROLLER to "auto_revoke_label") to mapOf("en" to "Remove permissions if app isn’t used (AOSP)"),
            ("com.example.preinstalled" to "usage_access") to mapOf("en" to "Erase everything"),
        ),
    )

    private val fallbacks = mapOf(
        "usage_access" to mapOf("en" to "Usage access", "fa" to "دسترسی به داده‌های مصرف", "zh" to "使用情况访问权限", "tr" to "Kullanım erişimi"),
        "private_dns" to mapOf("en" to "Private DNS", "fa" to "DNS خصوصی"),
        "vpn" to mapOf("en" to "VPN", "fa" to "VPN"),
        "only_persian" to mapOf("en" to "Persian only", "fa" to "فقط فارسی"),
    )

    private fun labels(
        rows: List<LabelRow>,
        phone: List<Locale> = english,
        own: List<Locale> = english,
        maker: String = "google",
        sdk: Int = 35,
        from: Phone = settings,
        system: (String) -> Boolean = { it != "com.example.notsystem" },
    ): SystemLabels {
        val shows = SystemLabels.ownLanguage(own)
        return SystemLabels(
            { rows }, maker, sdk, phone, own, from::read, system,
            // As Android picks Datapavan's resources: its own language for null, a language it lacks gives English.
            { key, at -> fallbacks[key]?.let { texts -> texts[(at ?: shows).language]?.takeIf { (at ?: shows).language in SystemLabels.LANGUAGES } ?: texts["en"] } },
        )
    }

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
    fun aLabelIsThePhonesOwnOnlyThroughItsMakersVerifiedRowOrOnAnAospMaker() {
        val rows = listOf(
            row("usage_access", name = "usage_access"),
            row("private_dns", name = "select_private_dns_configuration_title"),
            row("usage_access", maker = "samsung", apis = 30..30, name = "samsung_usage", verified = "SM-A405FN A405FNXXU4CWC3"),
        )
        // Samsung's own row, seen on its screen: its words, the phone's own.
        val samsung = labels(rows, maker = "samsung", sdk = 30)
        assertEquals("Usage data access", samsung.label("usage_access").text)
        assertEquals(LabelSource.PHONE, samsung.label("usage_access").source)
        // No Samsung row for Private DNS: AOSP's name as its Settings hold it, worded as Android's.
        assertEquals(LabelSource.ANDROID, samsung.label("private_dns").source)
        // A maker the data has never seen: every label read through AOSP's names is Android's, not the phone's.
        assertEquals(LabelSource.ANDROID, labels(rows, maker = "xiaomi").label("usage_access").source)
        assertEquals(listOf("Usage access", "Private DNS"), labels(rows, maker = "xiaomi").androids(listOf("usage_access", "private_dns")).map { it.text })
        // Google's Settings are AOSP's: its labels are the phone's own.
        assertEquals(LabelSource.PHONE, labels(rows, maker = "google").label("usage_access").source)
        assertTrue(labels(rows, maker = "google").androids(listOf("usage_access", "private_dns")).isEmpty())
    }

    @Test
    fun aMakersRowOutsideItsAndroidVersionsIsNotTried() {
        val rows = listOf(
            row("usage_access", name = "usage_access"),
            row("usage_access", maker = "samsung", apis = 30..30, name = "samsung_usage", verified = "SM-A405FN A405FNXXU4CWC3"),
        )
        val later = labels(rows, maker = "samsung", sdk = 33).label("usage_access")
        assertEquals("Usage access", later.text)
        assertEquals(LabelSource.ANDROID, later.source)
    }

    @Test
    fun androidElevensSwitchIsThePermissionControllersOfGoogleOrAosp() {
        val rows = listOf(
            row("unused_app_setting", apis = 30..30, pkg = CONTROLLER, name = "auto_revoke_label"),
            row("unused_app_setting", apis = 30..30, pkg = AOSP_CONTROLLER, name = "auto_revoke_label"),
            row("unused_app_setting", apis = 31..Int.MAX_VALUE, name = "usage_access"),
        )
        assertEquals("Remove permissions if app isn’t used", labels(rows, sdk = 30).label("unused_app_setting").text)
        // A phone without Google's permission controller reads AOSP's.
        val withoutGoogle = labels(rows, sdk = 30, system = { it != CONTROLLER })
        assertEquals("Remove permissions if app isn’t used (AOSP)", withoutGoogle.label("unused_app_setting").text)
        assertEquals("Usage access", labels(rows, sdk = 33).label("unused_app_setting").text)
    }

    @Test
    fun aMissingPackageResourceOrUnusableTextGoesOnToTheNextPlace() {
        val rows = listOf(
            row("usage_access", pkg = "com.example.gone", name = "usage_access"),
            row("usage_access", maker = "google", pkg = "com.example.notsystem", name = "usage_access", verified = "x"),
            row("usage_access", name = "missing"),
            row("usage_access", name = "blank"),
            row("usage_access", name = "placeholder"),
            row("usage_access", name = "format"),
            row("usage_access", name = "usage_access"),
        )
        val label = labels(rows).label("usage_access")
        assertEquals("Usage access", label.text)
        assertEquals(SETTINGS, label.row?.packageName)
        assertEquals("usage_access", label.row?.name)
        assertEquals(LabelSource.PHONE, label.source)
    }

    @Test
    fun noAppsResourceCanBreakTheScreenOrMakeItReadManyApps() {
        // A read that throws is no label.
        val failing = Phone(settings.strings, failing = setOf(SETTINGS))
        assertEquals(LabelSource.FALLBACK, labels(listOf(row("usage_access", name = "usage_access")), from = failing).label("usage_access").source)
        // A maker's rows that send the screen to many system apps: only the first three are read.
        val many = (1..5).map { row("usage_access", maker = "google", pkg = "com.example.app$it", name = "usage_access", verified = "x") } +
            row("usage_access", maker = "google", name = "usage_access", verified = "x")
        val phone = Phone(settings.strings)
        labels(many, from = phone).label("usage_access")
        assertEquals(3, phone.reads)
    }

    @Test
    fun withNoPlaceTheFallbackIsInThePhonesLanguageWhereDatapavanHasIt() {
        val none = listOf(row("usage_access", name = "missing"))
        // A Persian phone, Datapavan in English (the Galaxy A56 the other way round): Persian, with English beside it.
        val persianPhone = labels(none, phone = persian, own = english).label("usage_access")
        assertEquals(SystemLabel("دسترسی به داده‌های مصرف", persian[0], "Usage access", english[0], LabelSource.FALLBACK), persianPhone)
        // A Turkish phone: Datapavan has no Turkish, so its own language alone, even where a copy for Turkish exists.
        assertEquals(SystemLabel("Usage access", english[0], null, null, LabelSource.FALLBACK), labels(none, phone = listOf(locale("tr-TR"))).label("usage_access"))
        // Traditional Chinese is not Datapavan's Simplified: its own language alone.
        assertEquals("Usage access", labels(none, phone = listOf(locale("zh-TW"))).label("usage_access").text)
        assertEquals("使用情况访问权限", labels(none, phone = listOf(locale("zh-CN"))).label("usage_access").text)
        // No rows at all, as with a data pack that lacks the dataset.
        assertEquals("Usage access", labels(emptyList()).label("usage_access").text)
    }

    @Test
    fun nothingIsSetBesideALabelThatReadsTheSameInBothLanguages() {
        val rows = listOf(row("vpn", name = "vpn_settings_title"))
        assertNull(labels(rows, phone = persian, own = english).label("vpn").also)
        // The fallback too.
        assertNull(labels(listOf(row("vpn", name = "missing")), phone = persian, own = english).label("vpn").also)
    }

    @Test
    fun datapavansLanguageBesideIsItsOwnCopyWhereThePhoneHasNone() {
        val label = labels(listOf(row("only_persian", name = "only_persian")), phone = persian, own = english).label("only_persian")
        assertEquals("فقط فارسی", label.text)
        assertEquals("Persian only", label.also)
    }

    @Test
    fun aLabelIsReadInThePhonesOwnRegion() {
        val rows = listOf(row("battery_optimisation", name = "high_power_apps"))
        // The phone in American English: its words, not Samsung's British default.
        assertEquals("Optimize battery usage", labels(rows, phone = english, own = persian).label("battery_optimisation").text)
        // A phone in Persian with American English second, Datapavan in English: the English beside it is the phone's.
        val beside = labels(rows, phone = listOf(locale("fa-IR"), locale("en-US")), own = listOf(locale("en"))).label("battery_optimisation")
        assertEquals("Optimize battery usage", beside.also)
        // The debug dump reads each language in the phone's own region where the phone has it.
        assertEquals(locale("en-US"), PhoneLocales.forLanguage("en", listOf(locale("fa-IR"), locale("en-US"))))
        assertEquals(locale("fa"), PhoneLocales.forLanguage("fa", english))
        assertEquals(locale("zh-CN"), PhoneLocales.forLanguage("zh-CN", listOf(locale("zh-TW"))))
    }

    @Test
    fun datapavansLanguageIsTheOneItShows() {
        // A Hebrew phone with Datapavan following it: Datapavan shows English, so English is set beside the Hebrew label.
        assertEquals(Locale.ENGLISH, SystemLabels.ownLanguage(listOf(locale("he-IL"))))
        assertEquals(locale("fa"), SystemLabels.ownLanguage(listOf(locale("he-IL"), locale("fa"))))
        assertEquals(Locale.ENGLISH, SystemLabels.ownLanguage(listOf(locale("zh-TW"))))
        val hebrew = Phone(mapOf((SETTINGS to "usage_access") to mapOf("en" to "Usage access", "he" to "גישה לנתוני שימוש")))
        val label = labels(listOf(row("usage_access", name = "usage_access")), phone = listOf(locale("he-IL")), own = listOf(locale("he-IL")), from = hebrew).label("usage_access")
        assertEquals("גישה לנתוני שימוש", label.text)
        assertEquals("Usage access", label.also)
    }

    @Test
    fun alsoShowsWhereTheScriptsDifferToo() {
        val rows = listOf(row("usage_access", name = "usage_access"))
        assertTrue(OtherAppResources.sameWords(locale("zh-CN"), locale("zh-Hans-SG")))
        assertTrue(!OtherAppResources.sameWords(locale("zh-TW"), locale("zh-CN")))
        assertTrue(!OtherAppResources.sameWords(locale("zh-Hant"), locale("zh")))
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
            unused_app_setting	aosp	30-30	com.google.android.permissioncontroller	string	auto_revoke_label	-	aosp:permissioncontroller@android-11.0.0_r48..android-11.0.0_r48
            usage_access	samsung	30-35	com.android.settings	string	samsung_usage	SM-A405FN A405FNXXU4CWC3	device
            broken	aosp	29	com.android.settings	string	x	-	device
            broken	aosp	29-	com.android.settings	array	x	-	device
            broken	aosp	99999999999-	com.android.settings	string	x	-	device
            broken	aosp	29-	com.android.settings	string	android:string/x	-	device
            broken	aosp	29-	com.example.preinstalled	string	x	-	device
            broken	samsung	29-	com.android.settings	string	x	-	device
            broken	aosp	35-30	com.android.settings	string	x	-	device
            short	aosp	29-
        """.trimIndent()
        val rows = LabelRow.parse(text)
        assertEquals(3, rows.size)
        assertEquals(29..Int.MAX_VALUE, rows[0].apis)
        assertEquals("com.google.android.permissioncontroller", rows[1].packageName)
        assertEquals(30..35, rows[2].apis)
        assertEquals("SM-A405FN A405FNXXU4CWC3", rows[2].verified)
        assertNull(rows[0].verified)
        // At most eight rows of one key.
        val many = (1..12).joinToString("\n") { "k\taosp\t29-\tcom.android.settings\tstring\tname$it\t-\tdevice" }
        assertEquals(LabelRow.MAX_ROWS_PER_KEY, LabelRow.parse(many).size)
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
        // A control character is a space, not nothing.
        assertEquals("Proxy mode", OtherAppResources.clean("Proxy\nmode"))
        // AOSP's German screen lock carries soft hyphens and a zero-width space; Persian keeps its zero-width non-joiner,
        // and French its no-break space before a colon.
        assertEquals("Displaysperre", OtherAppResources.clean("Dis­play­sper­re"))
        assertEquals("App-Benachrichtigungen", OtherAppResources.clean("App-​Benachrichtigungen"))
        assertEquals("دسترس‌پذیری", OtherAppResources.clean("دسترس‌پذیری"))
        assertEquals("Notifications : lecture", OtherAppResources.clean("Notifications : lecture"))
        val long = OtherAppResources.clean("x".repeat(200))
        assertEquals(OtherAppResources.MAX, long.length)
        assertTrue(long.endsWith("…"))
        // A character outside the basic plane is never cut in two.
        val emoji = OtherAppResources.clean("🔒".repeat(100))
        assertEquals(OtherAppResources.MAX, emoji.codePointCount(0, emoji.length))
        assertTrue(emoji.dropLast(1).all { it.isSurrogate() })
    }

    private companion object {
        const val SETTINGS = "com.android.settings"
        const val CONTROLLER = "com.google.android.permissioncontroller"
        const val AOSP_CONTROLLER = "com.android.permissioncontroller"
    }
}
