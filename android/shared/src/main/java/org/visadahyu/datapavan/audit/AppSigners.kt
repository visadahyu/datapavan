package org.visadahyu.datapavan.audit

/** The signing certificates of an installed app, as SHA-256 digests in lowercase hex. */
data class AppSigning(
    /** The certificates that sign the app now: one, or several for an app with several signers. */
    val current: List<String>,
    /** For an app with one signer, its rotation history from the oldest key to the current one. */
    val history: List<String>,
    /** Whether a current certificate is Android's debug certificate (`CN=Android Debug`). */
    val debug: Boolean,
)

/** One official certificate from `data/app-signers/signers.tsv` (ADR 0018). */
data class SignerRecord(
    val sha256: String,
    /** 1 for a fingerprint the developer publishes, down to 5 for a single unconfirmed reading. */
    val grade: Int,
    /** Whose key it is: `developer`, `google` or `fdroid`. */
    val controller: String,
    val debug: Boolean,
)

/** An app whose official certificates are known. */
data class KnownApp(
    val packageName: String,
    val name: String,
    /** Every official channel's key is recorded, so any other key means a modified copy. */
    val closed: Boolean,
    val records: List<SignerRecord>,
)

/** What the app's signature says about an installed copy (ADR 0018). */
sealed interface SignatureVerdict {
    /** The name of the known app. */
    val app: String

    /** Signed with a key recorded for this app. [pastKeyOnly]: only an older key in its lineage matched. */
    data class Genuine(override val app: String, val controller: String, val pastKeyOnly: Boolean) : SignatureVerdict

    /** A listed app with a key not recorded for it. Not a warning: most such copies come from a store whose key is not known yet. */
    data class UnknownKey(override val app: String, val fingerprint: String) : SignatureVerdict

    /** Positive evidence that someone other than the developer signed this copy. */
    data class Modified(override val app: String, val fingerprint: String, val debugKey: Boolean) : SignatureVerdict

    /** A genuine build of a known app under another package name, such as a disguised build. */
    data class Disguised(override val app: String) : SignatureVerdict
}

/** The list of official certificates, and the rules that judge an installed copy against it. */
class AppSigners(apps: List<KnownApp>) {
    private val byPackage = apps.associateBy { it.packageName }

    /** Developer keys, for recognising a known app under another name. Keys held by F-Droid or Google identify one build only. */
    private val byDeveloperKey: Map<String, KnownApp> = apps
        .flatMap { app -> app.records.filter { it.controller == "developer" && !it.debug }.map { it.sha256 to app } }
        .toMap()

    val size: Int get() = byPackage.size

    /**
     * Judges [signing] of [packageName]. [fresh] is false once the data pack is more than six months
     * old: keys change, so a closed key set no longer proves that another key is a modification.
     */
    fun judge(packageName: String, signing: AppSigning?, fresh: Boolean): SignatureVerdict? {
        signing ?: return null
        val known = byPackage[packageName]
        if (known == null) {
            val single = signing.current.singleOrNull() ?: return null
            return byDeveloperKey[single]?.let { SignatureVerdict.Disguised(it.name) }
        }
        val recorded = known.records.associateBy { it.sha256 }
        if (signing.current.size > 1) {
            // Several signers: every one of them must be recorded.
            if (signing.current.all { it in recorded }) {
                return SignatureVerdict.Genuine(known.name, recorded.getValue(signing.current.first()).controller, pastKeyOnly = false)
            }
        } else {
            val current = signing.current.firstOrNull() ?: return null
            recorded[current]?.let { return SignatureVerdict.Genuine(known.name, it.controller, pastKeyOnly = false) }
            signing.history.firstOrNull { it in recorded }?.let {
                return SignatureVerdict.Genuine(known.name, recorded.getValue(it).controller, pastKeyOnly = true)
            }
        }
        val fingerprint = signing.current.joinToString(" ")
        val provenRecords = known.records.isNotEmpty() && known.records.all { it.grade <= MAX_PROVEN_GRADE }
        val closedAndFresh = known.closed && fresh && provenRecords
        // A debug certificate on an app whose official builds never use one.
        val strayDebugKey = signing.debug && known.records.none { it.debug } &&
            known.records.any { it.grade <= MAX_PROVEN_GRADE }
        return when {
            strayDebugKey -> SignatureVerdict.Modified(known.name, fingerprint, debugKey = true)
            closedAndFresh -> SignatureVerdict.Modified(known.name, fingerprint, debugKey = false)
            else -> SignatureVerdict.UnknownKey(known.name, fingerprint)
        }
    }

    companion object {
        const val APPS_PATH = "app-signers/apps.tsv"
        const val SIGNERS_PATH = "app-signers/signers.tsv"

        /** Grades 1 to 4 are evidence; grade 5 is a single reading. */
        private const val MAX_PROVEN_GRADE = 4

        /** Reads `apps.tsv` and `signers.tsv` as `data/app-signers/update.py` writes them. Malformed lines are skipped. */
        fun parse(apps: String, signers: String): AppSigners {
            val records = rows(signers).mapNotNull { columns ->
                val grade = columns.getOrNull(2)?.toIntOrNull() ?: return@mapNotNull null
                if (columns.size < 6 || !SHA256.matches(columns[1])) return@mapNotNull null
                columns[0] to SignerRecord(columns[1], grade, columns[3].split(',').first(), columns[5] == "yes")
            }.groupBy({ it.first }, { it.second })
            val known = rows(apps).mapNotNull { columns ->
                if (columns.size < 3) return@mapNotNull null
                KnownApp(columns[0], columns[1], columns[2] == "yes", records[columns[0]].orEmpty())
            }
            return AppSigners(known)
        }

        private fun rows(tsv: String) = tsv.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
            .toList()

        private val SHA256 = Regex("[0-9a-f]{64}")
    }
}
