package org.visadahyu.datapavan.audit

/** A company and who controls it (`data/owners/entities.tsv`, ADR 0020). */
data class Entity(
    val id: String,
    val name: String,
    val parent: String?,
    /** How the parent controls it: `whole` or `majority` make one group; `joint` and `minority` do not. */
    val control: String?,
    val since: String,
    val until: String,
)

/** The company that runs the service an SDK sends data to, found by the SDK's class prefix. */
data class SdkOperator(
    /** Its id in the tracker scanner, at or above [Owners.FIRST_ID]. */
    val id: Int,
    val name: String,
    val entity: String,
    val since: String,
    val until: String,
    /** When the service shut down, as `YYYY-MM-DD`, or null while it runs. */
    val shutDown: String?,
)

/** What the app page says about who runs the services of the SDKs in one app. */
data class OwnerNotes(
    /** The company group that the app and some of its SDKs share, by name, or null. */
    val group: String?,
    /** Those SDKs, by name. */
    val sameGroup: List<String>,
    /** SDKs whose service has shut down, by name, with the date. */
    val shutDown: List<Pair<String, String>>,
)

/**
 * Which company runs each SDK's service, which company controls which, and which company publishes
 * which app (`data/owners`, ADR 0020). The SDKs' class prefixes join the tracker scanner's signatures.
 * Same group means both sides lead, through parents that hold the whole or a majority, to the same
 * company on the data's date; anything not recorded gives no note at all, never a guess.
 */
class Owners private constructor(
    private val entities: Map<String, Entity>,
    val operators: List<SdkOperator>,
    private val prefixes: Map<Int, String>,
    /** The publishing company of each recorded package and certificate. */
    private val publishers: Map<Pair<String, String>, String>,
) {
    private val byId = operators.associateBy { it.id }

    fun byId(id: Int): SdkOperator? = byId[id]

    /** The SDKs' class prefixes in the scanner's format (that of `data/exodus/trackers.tsv`). */
    fun signatureTsv(): String = operators.mapNotNull { operator ->
        prefixes[operator.id]?.let { "${operator.id}\t${operator.name}\t\t\t$it\t" }
    }.joinToString("\n")

    /** The company that publishes [packageName], by its current signer or one in its history. */
    fun publisher(packageName: String, signing: AppSigning?): String? {
        signing ?: return null
        return (signing.current + signing.history).firstNotNullOfOrNull { publishers[packageName to it] }
    }

    /** The company at the top of [entity]'s group on [date]: up through parents that hold it wholly or by majority. */
    fun group(entity: String, date: String): String? {
        var current = entities[entity] ?: return null
        repeat(entities.size) {
            val parent = current.parent?.let(entities::get)
            if (parent == null || current.control !in GROUP_CONTROL || !current.holdsOn(date)) return current.id
            current = parent
        }
        return null
    }

    /** What to say about [found] SDKs in an app published by [publisher], on [date]. */
    fun notes(publisher: String?, found: List<SdkOperator>, date: String): OwnerNotes {
        val active = found.filter { it.holdsOn(date) }
        val group = publisher?.let { group(it, date) }
        val sameGroup = if (group == null) {
            emptyList()
        } else {
            active.filter { it.shutDown == null && group(it.entity, date) == group }.map { it.name }.distinct()
        }
        val shutDown = found.mapNotNull { operator -> operator.shutDown?.takeIf { it <= date }?.let { operator.name to it } }.distinct()
        return OwnerNotes(group?.takeIf { sameGroup.isNotEmpty() }?.let { entities[it]?.name }, sameGroup, shutDown)
    }

    private fun Entity.holdsOn(date: String) = since <= date && (until.isEmpty() || date < until)
    private fun SdkOperator.holdsOn(date: String) = since <= date && (until.isEmpty() || date < until)

    companion object {
        const val ENTITIES_PATH = "owners/entities.tsv"
        const val OPERATORS_PATH = "owners/sdk-operators.tsv"
        const val PUBLISHERS_PATH = "owners/publishers.tsv"
        const val FIRST_ID = 3_000_000

        private val GROUP_CONTROL = setOf("whole", "majority")
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val DATE = Regex("\\d{4}-\\d{2}-\\d{2}")

        /** Reads the three files as `data/owners` holds them. Malformed lines are skipped. */
        fun parse(entities: String, operators: String, publishers: String): Owners {
            val known = rows(entities).filter { it.size >= 7 }.associate { columns ->
                columns[0] to Entity(
                    columns[0], columns[1], columns[3].takeIf { it != "-" && it.isNotEmpty() },
                    columns[4].takeIf { it.isNotEmpty() }, columns[5], columns[6],
                )
            }
            val usable = rows(operators).filter { it.size >= 8 && it[3] in known && it[7] == "1" }
            val list = usable.mapIndexed { index, columns ->
                SdkOperator(FIRST_ID + index, columns[1], columns[3], columns[4], columns[5], columns[6].takeIf { DATE.matches(it) })
            }
            return Owners(
                known,
                list,
                list.zip(usable).associate { (operator, columns) -> operator.id to columns[2] },
                rows(publishers).filter { it.size >= 3 && SHA256.matches(it[1]) && it[2] in known }
                    .associate { (it[0] to it[1]) to it[2] },
            )
        }

        private fun rows(tsv: String) = tsv.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
            .toList()
    }
}
