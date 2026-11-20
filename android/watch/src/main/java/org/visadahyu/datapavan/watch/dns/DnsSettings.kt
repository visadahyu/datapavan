package org.visadahyu.datapavan.watch.dns

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import java.io.File
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.watch.Engine
import org.visadahyu.datapavan.watch.WatchPacks

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
        append("choice ").append(choice.engine).append('\n')
        append("pairs ").append(pairs.ifEmpty { "default" }).append('\n')
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
             * A resolver the user typed, or null with the reason it was refused: a DoH URL (`https://...`) or a DoT
             * host, and at least one address, since Watch never looks a resolver's name up in plain DNS.
             */
            fun custom(at: String, addresses: String): Choice? {
                val list = addresses.split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() }
                if (list.isEmpty() || list.any { Exchanger.numeric(it) == null }) return null
                val trimmed = at.trim()
                return when {
                    trimmed.startsWith("https://") && trimmed.length > 8 && ' ' !in trimmed -> Custom(false, trimmed, list)
                    trimmed.matches(HOST) -> Custom(true, trimmed, list)
                    else -> null
                }
            }

            private val HOST = Regex("^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")
        }
    }

    companion object {
        private const val CHOICE = "choice"
        private const val STRICT = "strict"
        private const val PAIRS = "pairs"
        private const val NOTIFY = "notify"

        /** The tables of the data pack this reads. */
        const val RELAYS = "odoh/relays.tsv"
        const val TARGETS = "odoh/targets.tsv"
        const val PAIR_TABLE = "odoh/pairs.tsv"
        const val PRESETS = "dns-presets/presets.tsv"

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
            return listOf(RELAYS, TARGETS, PAIR_TABLE, PRESETS).map { store.text(it).orEmpty() }
        }

        /** Hands the engine the tables and the user's setting, for the engines to come and the one that runs. */
        fun apply(context: Context): IntArray {
            val (relays, targets, pairs, presets) = tables(context)
            return Engine.nativeDns(relays, targets, pairs, presets, of(context).engineSetting())
        }

        /** The ways the screen offers. */
        fun catalogue(context: Context): DnsCatalogue {
            val (relays, targets, pairs, presets) = tables(context)
            return DnsCatalogue.parse(Engine.nativeDnsCatalogue(relays, targets, pairs, presets))
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

    /** A resolver the user may choose, with its card. */
    data class Preset(
        val id: String,
        val name: String,
        val operator: String,
        val country: String,
        val dot: Boolean,
        val logging: String,
        val audit: String,
        val filtering: String,
        val policy: String,
    )

    companion object {
        /** Reads `nativeDnsCatalogue`'s lines. */
        fun parse(text: String): DnsCatalogue {
            val relays = linkedMapOf<String, Party>()
            val targets = linkedMapOf<String, Party>()
            val defaults = mutableListOf<Pair<String, String>>()
            val allowed = mutableListOf<Pair<String, String>>()
            val presets = mutableListOf<Preset>()
            for (line in text.lines()) {
                val f = line.split('\t')
                when (f[0]) {
                    "relay" -> if (f.size >= 5) relays[f[1]] = Party(f[1], f[2], f[3], f[4])
                    "target" -> if (f.size >= 6) targets[f[1]] = Party(f[1], f[2], f[3], f[4])
                    "pair" -> if (f.size >= 3) defaults += f[1] to f[2]
                    "allowed" -> if (f.size >= 3) allowed += f[1] to f[2]
                    "preset" -> if (f.size >= 10) presets += Preset(f[1], f[2], f[3], f[4], f[5] == "dot", f[6], f[7], f[8], f[9])
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
            )
        }
    }
}
