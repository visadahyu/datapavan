package org.visadahyu.datapavan.audit

/** Why a system signing key cannot be trusted (`data/system-keys`, ADR 0023). */
enum class KeyKind {
    /** One of AOSP's test keys, whose private halves are public. */
    AOSP_TEST,

    /** One of Google's development keys, used for emulator and test images. */
    GOOGLE_DEV,

    /** A maker's platform key on Google's 2022 list of keys that signed malware. */
    LEAKED,
}

/** Where an app on the phone came from. */
enum class Origin { SYSTEM_IMAGE, UPDATED_SYSTEM_APP, INSTALLED_LATER }

/** What the phone's system key says about one app (ADR 0023). */
data class KeyFacts(
    /** Signed with the key that signs the package `android` on this phone. */
    val systemKey: Boolean,
    /** Runs as the system user, `android.uid.system`. */
    val runsAsSystem: Boolean,
    /** Why one of its signing keys cannot be trusted, or null. */
    val untrusted: KeyKind?,
    val origin: Origin,
    /** Installed from Google Play or from the phone maker's own store, by what the installer reported. */
    val fromTrustedStore: Boolean,
    /**
     * Signed with this phone's system key and installed with no installer: put there by the phone's
     * own setup, as Samsung does with apps a user may later remove. An app installed from a file always
     * has an installer; one installed over adb has none, but adb needs USB debugging, a finding of its own.
     */
    val fromSetup: Boolean = false,
)

/**
 * The fingerprints of system signing keys that cannot be trusted, and the rules that read an app's
 * signing against this phone's system key. The system key itself is read on the phone, from the
 * package `android`; no list of makers' keys is shipped (ADR 0023).
 */
class SystemKeys private constructor(private val keys: Map<String, KeyKind>) {

    fun kind(sha256: String): KeyKind? = keys[sha256]

    /** The kind of the first untrusted key among [signing]'s current and past keys. */
    fun untrusted(signing: AppSigning?): KeyKind? = signing?.let { (it.current + it.history).firstNotNullOfOrNull(keys::get) }

    /**
     * [platform] is the signing of the package `android`; [manufacturer] what the phone reports as its
     * maker, which picks the maker's store.
     */
    fun facts(app: AppFacts, platform: AppSigning?, manufacturer: String): KeyFacts {
        val systemKeys = platform?.current.orEmpty().toSet()
        val signedWithSystemKey = app.signing != null && (app.signing.current + app.signing.history).any { it in systemKeys }
        val origin = when {
            !app.isSystem -> Origin.INSTALLED_LATER
            app.updatedSystemApp -> Origin.UPDATED_SYSTEM_APP
            else -> Origin.SYSTEM_IMAGE
        }
        val stores = setOf(PLAY_STORE) + MAKER_STORES[manufacturer.lowercase()].orEmpty()
        return KeyFacts(
            signedWithSystemKey, app.uid == SYSTEM_UID, untrusted(app.signing), origin, app.installer in stores,
            fromSetup = signedWithSystemKey && app.installer == null,
        )
    }

    companion object {
        const val PATH = "system-keys/keys.tsv"
        const val SYSTEM_UID = 1000
        private const val PLAY_STORE = "com.android.vending"
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val KINDS = mapOf("aosp-test" to KeyKind.AOSP_TEST, "google-dev" to KeyKind.GOOGLE_DEV, "leaked" to KeyKind.LEAKED)

        /** The makers' own app stores, by the maker the phone reports (`Build.MANUFACTURER`). */
        private val MAKER_STORES = mapOf(
            "samsung" to setOf("com.sec.android.app.samsungapps"),
            "xiaomi" to setOf("com.xiaomi.market", "com.xiaomi.mipicks"),
            "huawei" to setOf("com.huawei.appmarket"),
            "honor" to setOf("com.hihonor.appmarket"),
            "oppo" to setOf("com.heytap.market", "com.oppo.market"),
            "realme" to setOf("com.heytap.market", "com.oppo.market"),
            "oneplus" to setOf("com.heytap.market", "com.oppo.market"),
            "vivo" to setOf("com.bbk.appstore"),
        )

        /** Reads `keys.tsv` as `data/system-keys` holds it. Malformed lines are skipped. */
        fun parse(tsv: String): SystemKeys = SystemKeys(
            tsv.lineSequence()
                .filter { it.isNotBlank() && !it.startsWith("#") }
                .map { it.split('\t') }
                .filter { it.size >= 2 && SHA256.matches(it[0]) && it[1] in KINDS }
                .associate { it[0] to KINDS.getValue(it[1]) },
        )
    }
}
