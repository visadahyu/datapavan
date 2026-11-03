package org.visadahyu.datapavan.audit

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.IOException

/**
 * The state that a plan item concerns (ADR 0026, point 8): for an app, whether it is installed and
 * enabled and what it holds; for the phone, debugging and user certificate authorities.
 */
data class ItemState(
    val installed: Boolean = true,
    val enabled: Boolean = true,
    /** Granted permissions with the dangerous protection level. */
    val permissions: Set<String> = emptySet(),
    val special: Set<SpecialAccess> = emptySet(),
    val vpn: Boolean = false,
    val usbDebugging: Boolean = false,
    val wirelessDebugging: Boolean = false,
    val authorities: Int = 0,
) {
    companion object {
        val UNINSTALLED = ItemState(installed = false, enabled = false)

        fun of(app: AppFacts?) = app?.let { ItemState(true, it.enabled, it.grantedDangerous.toSet(), it.special, it.vpnAuthorised) } ?: UNINSTALLED

        fun of(device: DeviceFacts) =
            ItemState(usbDebugging = device.usbDebugging, wirelessDebugging = device.wirelessDebugging, authorities = device.userCertificateAuthorities.size)
    }
}

/** Something that the user removed on a system screen. */
enum class ChangeKind { UNINSTALLED, DISABLED, PERMISSION_REMOVED, SPECIAL_REMOVED, VPN_REMOVED, USB_DEBUGGING_OFF, WIRELESS_DEBUGGING_OFF, AUTHORITY_REMOVED }

/** [detail] names the permission or special access. */
data class Change(val kind: ChangeKind, val detail: String? = null)

/** How a card ended. */
enum class Outcome { CHANGED, NOTHING_CHANGED, KEPT, SKIPPED }

/** One card of a session: the state before, and after the user came back from the screens they opened. */
data class JournalEntry(
    /** The start of the session, which identifies it. */
    val session: Long,
    val at: Long,
    val reason: PlanReason,
    /** Null for the phone's own items. */
    val packageName: String?,
    val opened: List<Screen>,
    val before: ItemState,
    val after: ItemState,
    val outcome: Outcome,
) {
    val key: String get() = PlanItem.key(reason, packageName)
    val changes: List<Change> get() = Journal.changes(before, after)
}

/** The answer to the plan's one question, three days after a session, whether everything still works. */
enum class HealthAnswer { WORKS, SOMETHING_WRONG }

data class JournalSession(val start: Long, val level: PlanLevel, val answer: HealthAnswer? = null)

/** The journal's rules and contents (ADR 0026, point 8): pure, so that they can be unit-tested. */
data class Journal(val sessions: List<JournalSession> = emptyList(), val entries: List<JournalEntry> = emptyList()) {

    fun withSession(session: JournalSession) = copy(sessions = sessions.filter { it.start != session.start } + session)

    /** Adds [entry], replacing an earlier entry of the same card in the same session. */
    fun withEntry(entry: JournalEntry) = copy(entries = entries.filterNot { it.session == entry.session && it.key == entry.key } + entry)

    fun answered(session: Long, answer: HealthAnswer) = copy(sessions = sessions.map { if (it.start == session) it.copy(answer = answer) else it })

    fun entriesOf(session: Long) = entries.filter { it.session == session }

    /** Items whose latest entry kept them as they were, with the state they were kept in. */
    fun kept(): Map<String, ItemState> = entries.groupBy { it.key }
        .mapValues { (_, list) -> list.maxBy { it.at } }
        .filterValues { it.outcome == Outcome.KEPT }
        .mapValues { (_, entry) -> entry.after }

    /** The oldest unanswered session that changed something and ended at least [HEALTH_DAYS] days before [now]. */
    fun healthCheckDue(now: Long): JournalSession? = sessions.sortedBy { it.start }.firstOrNull { session ->
        val changed = entriesOf(session.start).filter { it.outcome == Outcome.CHANGED }
        session.answer == null && changed.isNotEmpty() && now - changed.maxOf { it.at } >= HEALTH_DAYS * UsageFacts.DAY
    }

    companion object {
        const val HEALTH_DAYS = 3

        /** What the user removed between [before] and [after]; an uninstall says it all. */
        fun changes(before: ItemState, after: ItemState): List<Change> = buildList {
            if (before.installed && !after.installed) {
                add(Change(ChangeKind.UNINSTALLED))
                return@buildList
            }
            if (before.enabled && !after.enabled) add(Change(ChangeKind.DISABLED))
            (before.permissions - after.permissions).sorted().mapTo(this) { Change(ChangeKind.PERMISSION_REMOVED, it) }
            (before.special - after.special).sortedBy { it.ordinal }.mapTo(this) { Change(ChangeKind.SPECIAL_REMOVED, it.name) }
            if (before.vpn && !after.vpn) add(Change(ChangeKind.VPN_REMOVED))
            if (before.usbDebugging && !after.usbDebugging) add(Change(ChangeKind.USB_DEBUGGING_OFF))
            if (before.wirelessDebugging && !after.wirelessDebugging) add(Change(ChangeKind.WIRELESS_DEBUGGING_OFF))
            if (after.authorities < before.authorities) add(Change(ChangeKind.AUTHORITY_REMOVED))
        }

        /** Whether [change], recorded when the state was [after], has come back in [current], for example after an update. */
        fun cameBack(change: Change, after: ItemState, current: ItemState): Boolean = when (change.kind) {
            ChangeKind.UNINSTALLED -> current.installed
            ChangeKind.DISABLED -> current.installed && current.enabled
            ChangeKind.PERMISSION_REMOVED -> change.detail in current.permissions
            ChangeKind.SPECIAL_REMOVED -> current.special.any { it.name == change.detail }
            ChangeKind.VPN_REMOVED -> current.vpn
            ChangeKind.USB_DEBUGGING_OFF -> current.usbDebugging
            ChangeKind.WIRELESS_DEBUGGING_OFF -> current.wirelessDebugging
            ChangeKind.AUTHORITY_REMOVED -> current.authorities > after.authorities
        }
    }
}

/**
 * The journal's file format: one record per line, fields separated by tabs, lists by commas, and
 * `%`-escapes for those characters. Lines with an unknown record or value are skipped, so that an
 * older version can read a newer file.
 */
object JournalCodec {
    private const val HEADER = "datapavan-journal 1"

    fun encode(journal: Journal): String = buildString {
        appendLine(HEADER)
        for (s in journal.sessions) appendLine(listOf("session", s.start, s.level.name, s.answer?.name ?: "-").joinToString("\t"))
        for (e in journal.entries) {
            val fields = listOf(
                "entry", e.session.toString(), e.at.toString(), e.reason.name, e.packageName?.let(::escape) ?: "-",
                e.opened.joinToString(",") { it.name }, e.outcome.name, state(e.before), state(e.after),
            )
            appendLine(fields.joinToString("\t"))
        }
    }

    fun decode(text: String): Journal {
        val lines = text.lines()
        if (lines.firstOrNull() != HEADER) return Journal()
        val sessions = mutableListOf<JournalSession>()
        val entries = mutableListOf<JournalEntry>()
        for (line in lines.drop(1)) {
            val f = line.split('\t')
            when (f.firstOrNull()) {
                "session" -> if (f.size == 4) {
                    val start = f[1].toLongOrNull() ?: continue
                    val level = enumOrNull<PlanLevel>(f[2]) ?: continue
                    sessions += JournalSession(start, level, if (f[3] == "-") null else enumOrNull<HealthAnswer>(f[3]) ?: continue)
                }
                "entry" -> if (f.size == 9) {
                    val opened = list(f[5]).mapNotNull { enumOrNull<Screen>(it) }.takeIf { it.size == list(f[5]).size } ?: continue
                    entries += JournalEntry(
                        session = f[1].toLongOrNull() ?: continue,
                        at = f[2].toLongOrNull() ?: continue,
                        reason = enumOrNull<PlanReason>(f[3]) ?: continue,
                        packageName = if (f[4] == "-") null else unescape(f[4]),
                        opened = opened,
                        outcome = enumOrNull<Outcome>(f[6]) ?: continue,
                        before = state(f[7]) ?: continue,
                        after = state(f[8]) ?: continue,
                    )
                }
            }
        }
        return Journal(sessions, entries)
    }

    /** Flags, then the authorities, permissions and special access, separated by `/`. */
    private fun state(s: ItemState): String = listOf(
        listOf(s.installed, s.enabled, s.vpn, s.usbDebugging, s.wirelessDebugging).joinToString("") { if (it) "1" else "0" },
        s.authorities.toString(),
        s.permissions.sorted().joinToString(",", transform = ::escape),
        s.special.sortedBy { it.ordinal }.joinToString(",") { it.name },
    ).joinToString("/")

    private fun state(text: String): ItemState? {
        val parts = text.split('/')
        if (parts.size != 4 || parts[0].length != 5 || parts[0].any { it != '0' && it != '1' }) return null
        val flags = parts[0].map { it == '1' }
        return ItemState(
            installed = flags[0], enabled = flags[1], vpn = flags[2], usbDebugging = flags[3], wirelessDebugging = flags[4],
            authorities = parts[1].toIntOrNull() ?: return null,
            permissions = list(parts[2]).map(::unescape).toSet(),
            special = list(parts[3]).map { enumOrNull<SpecialAccess>(it) ?: return null }.toSet(),
        )
    }

    private fun list(text: String) = if (text.isEmpty()) emptyList() else text.split(',')

    private inline fun <reified T : Enum<T>> enumOrNull(name: String): T? = enumValues<T>().firstOrNull { it.name == name }

    private val ESCAPED = listOf('%', '\t', '\n', '\r', ',', '/')

    internal fun escape(text: String): String = buildString {
        for (c in text) if (c in ESCAPED) append('%').append("%02X".format(c.code)) else append(c)
    }

    internal fun unescape(text: String): String = buildString {
        var i = 0
        while (i < text.length) {
            val code = if (text[i] == '%' && i + 2 < text.length) text.substring(i + 1, i + 3).toIntOrNull(16) else null
            if (code != null) {
                append(code.toChar())
                i += 3
            } else {
                append(text[i])
                i++
            }
        }
    }
}

/**
 * Keeps the journal in app-private storage (ADR 0026, point 8). Nothing leaves the phone, and backups
 * exclude it like all of Datapavan's data. Writes are atomic, so a crash never leaves half a journal.
 */
class JournalStore(context: Context) {
    private val file = AtomicFile(File(context.filesDir, "journal.txt"))

    fun load(): Journal = try {
        JournalCodec.decode(file.readFully().toString(Charsets.UTF_8))
    } catch (_: IOException) {
        Journal()
    }

    fun save(journal: Journal) {
        val out = file.startWrite()
        try {
            out.write(JournalCodec.encode(journal).toByteArray(Charsets.UTF_8))
            file.finishWrite(out)
        } catch (e: IOException) {
            file.failWrite(out)
            throw e
        }
    }

    fun delete() = file.delete()
}
