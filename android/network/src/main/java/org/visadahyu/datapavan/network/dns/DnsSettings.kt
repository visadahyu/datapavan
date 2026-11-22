package org.visadahyu.datapavan.network.dns

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import java.io.File
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.network.Engine
import org.visadahyu.datapavan.network.WatchPacks

/**
 * The user's setting for the names of apps that go directly (W8, part 1, ADR 0042): their own resolver (a preset, or
 * a DoH or DoT one they give) or none, which means Oblivious DoH; the strict setting; the ODoH pairs, the defaults or
 * the user's; and whether a notification says so while names go to the network's resolver. Nothing of the names
 * themselves is kept.
 */
class DnsSettings private constructor(private val prefs: SharedPreferences) {
    /** The user's resolver. */
    var choice: Choice
        get() = Choice.read(prefs.getString(CHOICE, null))
        set(value) = prefs.edit { putString(CHOICE, value.written) }

    /** Never the network's resolver for a name of the internet. */
    var strict: Boolean
        get() = prefs.getBoolean(STRICT, false)
        set(value) = prefs.edit { putBoolean(STRICT, value) }

    /** "Only this resolver": the user's own resolver alone, nothing else asked (W8's fix round, review R-M1). */
    var only: Boolean
        get() = prefs.getBoolean(ONLY, false)
        set(value) = prefs.edit { putBoolean(ONLY, value) }

    /** Debug builds, for the DNS lab's check of a rotated key: `LOW HIGH` seconds a key's fetch waits, or empty. */
    var refreshForTests: String
        get() = prefs.getString(REFRESH, "").orEmpty()
        set(value) = prefs.edit { putString(REFRESH, value) }

    /** The user's pairs, `relay>target` by commas; empty for the defaults. */
    var pairs: String
        get() = prefs.getString(PAIRS, "").orEmpty()
        set(value) = prefs.edit { putString(PAIRS, value) }

    /** Whether a notification shows while names go to the network's resolver. Off unless the user turns it on. */
    var notify: Boolean
        get() = prefs.getBoolean(NOTIFY, false)
        set(value) = prefs.edit { putBoolean(NOTIFY, value) }

    /** The setting as the engine reads it (`DnsConfig::read`). */
    fun engineSetting(): String = buildString {
        append("strict ").append(if (strict) 1 else 0).append('\n')
        append("only ").append(if (only && choice != Choice.Odoh) 1 else 0).append('\n')
        append("choice ").append(choice.engine).append('\n')
        append("pairs ").append(pairs.ifEmpty { "default" }).append('\n')
        if (refreshForTests.isNotEmpty()) append("refresh ").append(refreshForTests).append('\n')
    }

    /** The user's resolver. */
    sealed interface Choice {
        /** How it is kept. */
        val written: String

        /** How the engine reads it. */
        val engine: String

        /** None: Oblivious DoH. */
        data object Odoh : Choice {
            override val written = "odoh"
            override val engine = "odoh"
        }

        /** A preset of the data pack. */
        data class Preset(val id: String) : Choice {
            override val written get() = "preset $id"
            override val engine get() = "preset $id"
        }

        /** The user's DoH URL or DoT host (`host` or `host:port`), with the addresses the user gave. */
        data class Custom(val dot: Boolean, val at: String, val addresses: List<String>) : Choice {
            override val written get() = "${if (dot) "dot" else "doh"} $at ${addresses.joinToString(",")}"
            override val engine get() = written
        }

        companion object {
            /** A choice as kept; Oblivious DoH for anything that does not read. */
            fun read(text: String?): Choice {
                val words = text.orEmpty().trim().split(' ').filter { it.isNotEmpty() }
                return when {
                    words.size == 2 && words[0] == "preset" -> Preset(words[1])
                    words.size in 2..3 && words[0] in setOf("doh", "dot") -> Custom(
                        dot = words[0] == "dot",
                        at = words[1],
                        addresses = words.getOrNull(2)?.split(',')?.filter { it.isNotEmpty() }.orEmpty(),
                    )
                    else -> Odoh
                }
            }

            /**
             * A resolver the user typed, or null when it does not read: a DoH URL (`https://host[:port][/path]`) or a
             * DoT host (`host[:port]`), read as the engine reads them (`Url::parse`, `dot_url`: a host of letters,
             * digits, hyphens and dots, a path of RFC 3986's unreserved characters and `/`, no query, user or space;
             * W8's fix round), and one to sixteen IP addresses, since Watch never looks a resolver's name up in plain
             * DNS. Persian and Arabic digits and commas, as a Persian keyboard types them, read as ASCII ones
             * (review R-m6). Nothing typed makes it throw (review S-M2).
             */
            fun custom(at: String, addresses: String): Choice? = try {
                val list = ascii(addresses).split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() }
                val trimmed = ascii(at).trim()
                when {
                    list.isEmpty() || list.size > MAX_ADDRESSES || list.any { Exchanger.numeric(it) == null } -> null
                    trimmed.startsWith("https://") -> trimmed.takeIf { dohUrl(it) }?.let { Custom(false, it, list) }
                    hostPort(trimmed) -> Custom(true, trimmed.lowercase(), list)
                    else -> null
                }
            } catch (e: RuntimeException) {
                null
            }

            private const val MAX_ADDRESSES = 16

            /** [text] with Persian and Arabic-Indic digits and the Arabic comma as their ASCII forms. */
            internal fun ascii(text: String): String = buildString(text.length) {
                for (c in text) {
                    append(
                        when (c) {
                            in '\u06F0'..'\u06F9' -> '0' + (c - '\u06F0')
                            in '\u0660'..'\u0669' -> '0' + (c - '\u0660')
                            '\u060C' -> ','
                            else -> c
                        },
                    )
                }
            }

            /** Whether [text] is a DoH URL the engine reads: `https://`, a [hostPort], and a path of unreserved characters. */
            internal fun dohUrl(text: String): Boolean {
                if (!text.startsWith("https://") || text.any { it.code <= 0x20 || it.code >= 0x7f }) return false
                val rest = text.removePrefix("https://")
                val slash = rest.indexOf('/')
                val path = if (slash < 0) "/" else rest.substring(slash)
                return hostPort(if (slash < 0) rest else rest.substring(0, slash)) &&
                    path.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "/-._~" }
            }

            /** Whether [text] is `host` or `host:port`: labels of ASCII letters, digits and hyphens, a port of 1 to 65535. */
            internal fun hostPort(text: String): Boolean {
                val colon = text.lastIndexOf(':')
                val host = if (colon < 0) text else text.substring(0, colon)
                val port = if (colon < 0) null else text.substring(colon + 1)
                if (port != null && (port.isEmpty() || port.length > 5 || port.any { it !in '0'..'9' } || port.toInt() !in 1..65535)) return false
                return host.isNotEmpty() && host.length <= 253 && host.split('.').all { label ->
                    label.isNotEmpty() && label.length <= 63 && label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
                }
            }

        }
    }

    companion object {
        private const val CHOICE = "choice"
        private const val STRICT = "strict"
        private const val ONLY = "only"
        private const val REFRESH = "refresh-for-tests"
        private const val PAIRS = "pairs"
        private const val NOTIFY = "notify"

        /** The tables of the data pack this reads. */
        const val RELAYS = "odoh/relays.tsv"
        const val TARGETS = "odoh/targets.tsv"
        const val PAIR_TABLE = "odoh/pairs.tsv"
        const val PRESETS = "dns-presets/presets.tsv"

        /** The ICANN section of the public suffix list (W8's fix round, review S-C1). */
        const val SUFFIXES = "public-suffix/icann.dat"

        /** Debug builds: the DNS lab's tables and root, put in Watch's files by scripts/verify-dns.sh, in place of the pack's. */
        const val LAB_DIR = "dnslab"

        @Volatile
        private var instance: DnsSettings? = null

        fun of(context: Context): DnsSettings = instance ?: synchronized(this) {
            instance ?: DnsSettings(context.applicationContext.getSharedPreferences("watch-dns", Context.MODE_PRIVATE)).also { instance = it }
        }

        /** The four tables: the DNS lab's in a debug build that has them, else the data pack's. */
        fun tables(context: Context): List<String> {
            val lab = File(context.filesDir, LAB_DIR)
            val debuggable = context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (debuggable && File(lab, "relays.tsv").isFile) {
                return listOf("relays.tsv", "targets.tsv", "pairs.tsv", "presets.tsv").map { File(lab, it).takeIf(File::isFile)?.readText().orEmpty() }
            }
            val store = try {
                DataPackStore.read(context, WatchPacks)
            } catch (e: RuntimeException) {
                return List(4) { "" }
            }
            val (relays, targets, pairs, presets) = listOf(RELAYS, TARGETS, PAIR_TABLE, PRESETS).map { store.text(it).orEmpty() }
            return listOf(forBuild(relays, debuggable), targets, pairs, presets)
        }

        /**
         * The relays' table as this build may use it (ADR 0055): a release build keeps a row only when its status, the
         * twelfth column, is `-`; any other value (`debug`, a misspelling, a value to come, a row whose columns moved)
         * and a row without the column stay out of it (review m7: fail closed). A debuggable build keeps every row. A
         * release build's engine and screen therefore never see the project's own relay until ADR 0055's gates pass.
         * The bundled pack has the column, and a pack is never older than it.
         */
        fun forBuild(relays: String, debuggable: Boolean): String = if (debuggable) relays else {
            relays.lineSequence().filter { line ->
                line.startsWith("#") || line.isBlank() || line.split('\t').getOrNull(11)?.trim() == "-"
            }.joinToString("\n")
        }

        /**
         * The public suffixes of the data pack, for [SearchDomains]; empty when the pack does not read, and then Watch
         * accepts no search domain at all.
         */
        fun suffixes(context: Context): PublicSuffixes = try {
            PublicSuffixes.parse(DataPackStore.read(context, WatchPacks).text(SUFFIXES).orEmpty())
        } catch (e: RuntimeException) {
            PublicSuffixes.parse("")
        }

        /** Hands the engine the tables and the user's setting, for the engines to come and the one that runs. */
        fun apply(context: Context): IntArray {
            val (relays, targets, pairs, presets) = tables(context)
            return Engine.nativeDns(relays, targets, pairs, presets, of(context).engineSetting())
        }

        /** The ways the screen offers. */
        fun catalogue(context: Context): DnsCatalogue {
            val (relays, targets, pairs, presets) = tables(context)
            return DnsCatalogue.parse(Engine.nativeDnsCatalogue(relays, targets, pairs, presets), relays, targets, presets)
        }
    }
}

/** The ways the data pack holds, as the engine reads them for the screen. */
data class DnsCatalogue(
    val relays: Map<String, Party>,
    val targets: Map<String, Party>,
    val defaults: List<Pair<String, String>>,
    val allowed: List<Pair<String, String>>,
    val presets: List<Preset>,
) {
    /** Who stands behind a relay or a target. */
    data class Party(val id: String, val operator: String, val person: String, val jurisdictions: String)

    /**
     * A resolver the user may choose, with its card (W8's fix round, review R-M2): the operator, its seat's country
     * code, and the table's enumerated values, which the screen turns into translated words; the table's own
     * sentences stay in the data, for the record.
     */
    data class Preset(
        val id: String,
        val operator: String,
        val country: String,
        val dot: Boolean,
        /** `blocking`, `unfiltered` or `standard`. */
        val service: String,
        /** `totals`, `names-day`, `day`, `months` or `none`. */
        val logs: String,
        /** `none`, `harm` or `court`. */
        val blocks: String,
        /** `no` or `firm`. */
        val audited: String,
        val policy: String,
    ) {
        /** The service, as both of its protocols share it: the id without `-doh` or `-dot`. */
        val group: String get() = id.removeSuffix("-doh").removeSuffix("-dot")
    }

    companion object {
        /**
         * Reads `nativeDnsCatalogue`'s lines, which name the relays, targets and presets the engine read, the pairs,
         * and how each preset is reached, with their words from the tables themselves: [relaysTable] and
         * [targetsTable] (`odoh/relays.tsv`, `odoh/targets.tsv`: the operator, the person, the jurisdictions) and
         * [presetsTable] (`dns-presets/presets.tsv`: the cards' columns).
         */
        fun parse(text: String, relaysTable: String, targetsTable: String, presetsTable: String): DnsCatalogue {
            fun table(tsv: String, columns: Int) = tsv.lineSequence().filter { it.isNotBlank() && !it.startsWith("#") }
                .map { it.split('\t') }.filter { it.size >= columns }.associateBy { it[0] }
            val relayRows = table(relaysTable, 7)
            val targetRows = table(targetsTable, 8)
            val rows = table(presetsTable, 18)
            val relays = linkedMapOf<String, Party>()
            val targets = linkedMapOf<String, Party>()
            val defaults = mutableListOf<Pair<String, String>>()
            val allowed = mutableListOf<Pair<String, String>>()
            val presets = mutableListOf<Preset>()
            for (line in text.lines()) {
                val f = line.split('\t')
                when (f[0]) {
                    "relay" -> if (f.size >= 2) relayRows[f[1]]?.let { relays[f[1]] = Party(f[1], it[4], it[5], it[6]) }
                    "target" -> if (f.size >= 2) targetRows[f[1]]?.let { targets[f[1]] = Party(f[1], it[5], it[6], it[7]) }
                    "pair" -> if (f.size >= 3) defaults += f[1] to f[2]
                    "allowed" -> if (f.size >= 3) allowed += f[1] to f[2]
                    "preset" -> if (f.size >= 3) {
                        val row = rows[f[1]]
                        presets += Preset(
                            id = f[1],
                            operator = row?.get(2).orEmpty(),
                            country = row?.get(3).orEmpty(),
                            dot = f[2] == "dot",
                            service = row?.get(14).orEmpty(),
                            logs = row?.get(15).orEmpty(),
                            blocks = row?.get(16).orEmpty(),
                            audited = row?.get(17).orEmpty(),
                            policy = row?.get(11)?.takeIf { it.startsWith("https://") }.orEmpty(),
                        )
                    }
                }
            }
            return DnsCatalogue(relays, targets, defaults, allowed, presets)
        }
    }
}

/** The engine's state of the encrypted resolver, as `nativeDnsStatus` gives it. */
data class DnsStatus(
    /** `off`, `none`, a way (`odoh RELAY TARGET`, `odoh-tool RELAY TARGET`, `choice`, `doh-target TARGET`, `preset ID`). */
    val way: String,
    /** Seconds since names began to go to the network's resolver, or null. */
    val fallbackSeconds: Long?,
    /** Seconds since, in the strict setting, no encrypted way answered, or null. */
    val failingSeconds: Long?,
    val strict: Boolean,
    val validated: Boolean,
    val held: Int,
    /** The network's search domains in use: names under them go to its resolver when the internet does not know them. */
    val search: List<String> = emptyList(),
) {
    companion object {
        fun parse(text: String): DnsStatus {
            val lines = text.lines().associate { it.substringBefore(' ') to it.substringAfter(' ', "") }
            val way = lines["way"].orEmpty()
            val words = way.split(' ')
            return DnsStatus(
                way = way,
                fallbackSeconds = words.getOrNull(1)?.toLongOrNull()?.takeIf { words[0] == "fallback" },
                failingSeconds = words.getOrNull(1)?.toLongOrNull()?.takeIf { words[0] == "failing" },
                strict = lines["strict"] == "1",
                validated = lines["validated"] != "0",
                held = lines["held"]?.toIntOrNull() ?: 0,
                search = lines["search"].orEmpty().split(' ').filter { it.isNotEmpty() },
            )
        }
    }
}
