package org.visadahyu.datapavan.audit

/** What an SDK from `data/sdks` does (ADR 0019). */
enum class SdkCategory { TRAFFIC_SHARING, REMOTE_SUPPORT, SCREEN_RECORDING }

/** What a remote-support or screen-recording SDK can reach, according to its vendor. */
enum class SdkCapability { APP_SCREEN, WHOLE_SCREEN, APP_CONTROL, DEVICE_CONTROL, FILES, LIVE }

/** One SDK of the list, as its vendor publishes it. */
data class Sdk(
    /** Its id in the tracker scanner, at or above [SdkList.FIRST_ID] so that it never meets an εxodus id. */
    val id: Int,
    val name: String,
    val vendor: String,
    val category: SdkCategory,
    val capabilities: Set<SdkCapability>,
    /** The label of the opt-out switch where the vendor prescribes one, such as "Web Indexing". */
    val settingsLabel: String?,
    /** When its identifiers were last read in the vendor's artefact, as `YYYY-MM-DD`. */
    val checked: String,
)

/**
 * Traffic-sharing, remote-support and screen-recording SDKs (`data/sdks`, ADR 0019). Their shipped
 * identifiers join the tracker scanner's signatures, so one pass over an app's code finds both.
 */
class SdkList private constructor(val sdks: List<Sdk>, private val identifiers: Map<Int, List<String>>) {
    private val byId = sdks.associateBy { it.id }

    fun byId(id: Int): Sdk? = byId[id]

    /**
     * The identifiers that may reach the phone, in the scanner's format (that of
     * `data/exodus/trackers.tsv`): one line per SDK, its identifiers separated by `|`.
     */
    fun signatureTsv(): String = sdks.mapNotNull { sdk ->
        identifiers[sdk.id]?.takeIf { it.isNotEmpty() }?.let { "${sdk.id}\t${sdk.name}\t\t\t${it.joinToString("|")}\t" }
    }.joinToString("\n")

    companion object {
        const val SDKS_PATH = "sdks/sdks.tsv"
        const val SIGNATURES_PATH = "sdks/signatures.tsv"
        const val FIRST_ID = 1_000_000

        /** Grades 1 to 3 ship; 4 and 5 are the work queue. */
        private const val MAX_SHIPPED_GRADE = 3

        /** Kinds of identifier the class-name scanner can match. Native libraries come later. */
        private val CLASS_MATCHES = setOf("class", "class-prefix", "manifest-component")

        /** Reads `sdks.tsv` and `signatures.tsv` as `data/sdks/update.py` writes them. Malformed lines are skipped. */
        fun parse(sdks: String, signatures: String): SdkList {
            val shipped = rows(signatures).filter { columns ->
                columns.size >= 10 && columns[1] in CLASS_MATCHES && columns[3] == "high" &&
                    (columns[4].toIntOrNull() ?: Int.MAX_VALUE) <= MAX_SHIPPED_GRADE
            }
            val checked = shipped.groupBy({ it[0] }, { it[9] }).mapValues { (_, dates) -> dates.max() }
            val values = shipped.groupBy({ it[0] }, { it[2] })
            val list = rows(sdks).mapIndexedNotNull { index, columns ->
                if (columns.size < 4) return@mapIndexedNotNull null
                val category = when (columns[3]) {
                    "traffic-sharing" -> SdkCategory.TRAFFIC_SHARING
                    "remote-support" -> SdkCategory.REMOTE_SUPPORT
                    "screen-recording" -> SdkCategory.SCREEN_RECORDING
                    else -> return@mapIndexedNotNull null
                }
                val capabilities = columns.getOrNull(4).orEmpty().split(',').mapNotNull { name ->
                    SdkCapability.entries.firstOrNull { it.name == name.uppercase().replace('-', '_') }
                }.toSet()
                columns[0] to Sdk(
                    FIRST_ID + index, columns[1], columns[2], category, capabilities,
                    columns.getOrNull(5)?.takeIf { it.isNotBlank() }, checked[columns[0]].orEmpty(),
                )
            }
            return SdkList(list.map { it.second }, list.associate { (key, sdk) -> sdk.id to values[key].orEmpty() })
        }

        private fun rows(tsv: String) = tsv.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
            .toList()
    }
}
