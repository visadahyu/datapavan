package org.visadahyu.datapavan.datapack

import org.visadahyu.datapavan.core.NativeCore
import java.security.MessageDigest
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.util.Locale

/**
 * The datasets of one data pack (ADR 0015 and 0017, docs/DATA-PACKS.md): the files under `data/`
 * in the repository, by path, for example `exodus/trackers.tsv`.
 */
class DataPack internal constructor(
    /** The pack as read, which the ranges below point into. */
    internal val bytes: ByteArray,
    /** Where the signed payload starts in [bytes]; 0 for the APK's bare payload. */
    private val payloadStart: Int,
    /** Raised by one for every published pack. */
    val sequence: Int,
    /** The day the pack was made, as `YYYY-MM-DD`. */
    val date: String,
    /** Keys that may sign later packs, as signify public key lines. */
    val keys: List<String>,
    /** Keys that must no longer be trusted. */
    val revoked: List<String>,
    private val files: Map<String, IntRange>,
) {
    /** Every file in the pack, in ascending order. */
    val paths: List<String> get() = files.keys.toList()

    /** The datasets, which are the folders of the files: `attestation`, `exodus`, … */
    val datasets: List<String> get() = files.keys.map { it.substringBefore('/') }.distinct()

    fun file(path: String): ByteArray? = files[path]?.let { bytes.copyOfRange(it.first, it.last + 1) }

    fun text(path: String): String? = file(path)?.toString(Charsets.UTF_8)

    /**
     * SHA-256 of the payload, in lowercase hex. It is published with every pack, so that anyone can
     * compare it with the one on their phone; a pack signed with a stolen key and given to a few
     * people would not match (docs/DATA-PACKS.md).
     */
    val fingerprint: String by lazy {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(bytes, payloadStart, bytes.size - payloadStart)
        digest.digest().joinToString("") { "%02x".format(Locale.ROOT, it) }
    }
}

/** The value of a `name: value` line in a dataset's `SOURCE` file, for example its `retrieved` time. */
fun sourceField(source: String, name: String): String? =
    source.lineSequence().firstOrNull { it.startsWith("$name: ") }?.substringAfter(": ")?.trim()

/**
 * Joins the hard-wrapped lines of a notice into paragraphs, so that a narrow screen can wrap them. A
 * line joins the one before it when both have text and the same indentation, which is how the
 * LICENSE files under `data/` are written; the indentation itself is dropped.
 */
fun reflow(text: String): String {
    val paragraphs = mutableListOf<String>()
    var indent = -1
    for (line in text.lines()) {
        val words = line.trim()
        val depth = line.length - line.trimStart().length
        when {
            words.isEmpty() -> {
                if (paragraphs.lastOrNull()?.isNotEmpty() == true) paragraphs += ""
                indent = -1
            }
            depth == indent -> paragraphs[paragraphs.lastIndex] += " $words"
            else -> {
                paragraphs += words
                indent = depth
            }
        }
    }
    return paragraphs.joinToString("\n").trim()
}

/** Why a pack was not imported. The first eight come from the Rust engine, with its codes. */
enum class PackRefusal(internal val code: Int) {
    TOO_LARGE(1),
    NOT_SIGNED(2),
    UNKNOWN_KEY(3),
    BAD_SIGNATURE(4),
    NOT_PACK(5),
    UNSUPPORTED_VERSION(6),
    INVALID_HEADER(7),
    INVALID_KEY(8),

    /** Not newer than the pack in use. */
    NOT_NEWER(100),

    /** This build trusts no data-signing key, so it cannot import anything. */
    NO_TRUSTED_KEYS(101),

    /** The file could not be read. */
    UNREADABLE(102),
    ;

    internal companion object {
        fun of(code: Int): PackRefusal = entries.firstOrNull { it.code == code } ?: INVALID_HEADER
    }
}

/** A pack that was read, or why it was refused. */
sealed interface PackReading {
    /** [signer] is the index of the key that signed it, or -1 for a bare payload. */
    data class Read(val pack: DataPack, val signer: Int) : PackReading
    data class Refused(val reason: PackRefusal) : PackReading
}

/** Reads packs through the Rust engine, which checks a pack's signature before anything else. */
internal object PackReader {
    /** Checks that one of [trusted] signed [pack], then reads it. */
    fun signed(pack: ByteArray, trusted: List<String>): PackReading =
        decode(pack, NativeCore.readDataPack(pack, trusted.joinToString("\n")))

    /** Reads the bare payload from the APK, whose own signature covers it. */
    fun payload(payload: ByteArray): PackReading = decode(payload, NativeCore.readDataPayload(payload))

    /**
     * Decodes the engine's layout: `[0, signer, payloadStart, sequence, dateStart, dateLength, k, k ×
     * (start, length), r, r × (start, length), f, f × (pathStart, pathLength, dataStart, dataLength)]`,
     * with every start counted in [bytes], or `[code]` for a refused pack.
     */
    fun decode(bytes: ByteArray, layout: IntArray): PackReading {
        val status = layout.firstOrNull() ?: PackRefusal.INVALID_HEADER.code
        if (status != 0) return PackReading.Refused(PackRefusal.of(status))
        var next = 1
        fun take(): Int = layout[next++]
        fun text(): String {
            val start = take()
            return String(bytes, start, take(), Charsets.US_ASCII)
        }
        fun texts(): List<String> = List(take()) { text() }
        val signer = take()
        val payloadStart = take()
        val sequence = take()
        val date = text()
        val keys = texts()
        val revoked = texts()
        val files = buildMap {
            repeat(take()) {
                val path = text()
                val start = take()
                put(path, start until start + take())
            }
        }
        return PackReading.Read(DataPack(bytes, payloadStart, sequence, date, keys, revoked, files), signer)
    }
}

/**
 * The rules that decide which pack the app uses and which keys it trusts. Kept apart from storage so
 * that they can be tested on their own.
 *
 * The app's own pack, from the APK, names the keys pinned in this build. An imported pack may name
 * more, which is how a new key is announced in a pack signed by the old one, and either may revoke a
 * key. For each imported pack the app remembers its chain: the keys that signed it and the packs
 * that introduced its key, back to a key pinned in the APK. After an app update, an imported pack is
 * kept only while its chain starts at a key the new build still pins and contains no key it revokes.
 */
internal object DataPackRules {
    fun trustedKeys(bundled: DataPack, installed: DataPack?): List<String> {
        val revoked = (bundled.revoked + installed?.revoked.orEmpty()).toSet()
        return (bundled.keys + installed?.keys.orEmpty()).distinct().filter { it !in revoked }
    }

    /** A pack can only replace an older one, so an old pack with known problems cannot return. */
    fun refusal(candidate: DataPack, active: DataPack): PackRefusal? =
        if (candidate.sequence <= active.sequence) PackRefusal.NOT_NEWER else null

    /** The chain of a pack signed by [signer], imported over a pack with [chain]. */
    fun chainAfter(bundled: DataPack, chain: List<String>, signer: String): List<String> = when {
        signer in bundled.keys -> listOf(signer)
        signer in chain -> chain.subList(0, chain.indexOf(signer) + 1)
        else -> chain + signer
    }

    /**
     * Whether data from [date] is old enough to say so. Without a network the app cannot know that a
     * newer pack exists, or that someone keeps it from the user; it can only point at the date.
     */
    fun isStale(date: String, today: LocalDate): Boolean = try {
        LocalDate.parse(date).plusMonths(STALE_MONTHS).isBefore(today)
    } catch (_: DateTimeParseException) {
        false
    }

    private const val STALE_MONTHS = 6L

    /** Whether an imported pack still applies, for example after an app update. */
    fun keep(bundled: DataPack, installed: DataPack, chain: List<String>): Boolean =
        installed.sequence > bundled.sequence &&
            chain.isNotEmpty() && chain.first() in bundled.keys &&
            chain.none { it in bundled.revoked }
}
