package org.visadahyu.datapavan.watch.activity

import java.net.URI
import java.net.URISyntaxException
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.Owners

/**
 * How "Now" and each app's history mark a destination that the εxodus network signatures name (ADR 0046,
 * decision 2 (d), as the maintainer decided on 2026-11-19):
 *
 * - **no tracker mark for the app's own company group.** Where every tracker a destination's name matches
 *   belongs to the company group of the app itself (ADR 0020's entities, through parents holding them whole
 *   or by majority, as the audit's `OwnerNotes.group` decides it), the destination is told as the same company
 *   as the app, not as a tracker: an app of Google talking to Google's servers;
 * - **one mark for one broad signature.** Where several trackers of one company match a destination by the
 *   same alternative, as εxodus's `\.facebook\.com` names six of Facebook's, one mark names the company rather
 *   than each tracker;
 * - every other match is marked by its tracker's name, as before.
 *
 * A tracker's company is the entity whose own domain, the host of the Digital Asset Links file the owners'
 * table reads its apps from (`owners/publisher-sources.tsv`), is the host of the tracker's website in the
 * εxodus table or a domain above it; the app's company is its publisher by package and signing certificate
 * (`owners/publishers.tsv`). Where the table knows neither, nothing is guessed: the tracker is marked by its
 * name, and an app whose publisher the table does not know is never told as the same company as anything.
 */
object TrackerMarks {
    /** One alternative of a network signature that matched: its tracker's id, name and website, and itself. */
    data class Match(val id: Int, val name: String, val website: String, val alternative: String)

    sealed interface Mark {
        /** A tracker, by its name in the εxodus list. */
        data class Tracker(val name: String) : Mark

        /** Several trackers of one company that one broad signature names, by the company's name. */
        data class Company(val name: String) : Mark

        /** Trackers of the app's own company group: no tracker mark, the company's name instead. */
        data class SameCompany(val name: String) : Mark
    }

    /** The matches of one line of `Engine.nativeTrackersOf`: `id␟name␟website␟alternative`, tab-separated. */
    fun parse(line: String): List<Match> = line.split('\t').filter { it.isNotEmpty() }.mapNotNull { entry ->
        val fields = entry.split('\u001f')
        if (fields.size != 4) return@mapNotNull null
        fields[0].toIntOrNull()?.let { Match(it, fields[1], fields[2], fields[3]) }
    }

    /**
     * The marks of a destination's [matches], for an app of the company group [appGroup] (null where the
     * table does not know it): [groupOf] gives a tracker's company group, null where unknown, and [name] a
     * group's name. The app's own group first, then companies, then trackers, each once.
     */
    fun marks(matches: List<Match>, appGroup: String?, groupOf: (Match) -> String?, name: (String) -> String): List<Mark> {
        val groups = matches.associate { it.id to groupOf(it) }
        val same = matches.filter { appGroup != null && groups[it.id] == appGroup }.map { it.id }.toSet()
        val rest = matches.filter { it.id !in same }
        val covered = mutableSetOf<Int>()
        val companies = linkedSetOf<String>()
        for ((_, sharing) in rest.groupBy { it.alternative }) {
            val ids = sharing.map { it.id }.toSet()
            val group = ids.map { groups[it] }.toSet().singleOrNull()
            if (ids.size >= 2 && group != null) {
                companies += name(group)
                covered += ids
            }
        }
        return buildList {
            if (same.isNotEmpty() && appGroup != null) add(Mark.SameCompany(name(appGroup)))
            companies.forEach { add(Mark.Company(it)) }
            rest.filter { it.id !in covered }.map { it.name }.distinct().forEach { add(Mark.Tracker(it)) }
        }
    }
}

/**
 * The companies of `data/owners` (ADR 0020) as [TrackerMarks] reads them: who publishes an app, whose website a
 * tracker's is, and the company group of each on [date] (`YYYY-MM-DD`).
 */
class Companies(
    private val owners: Owners,
    publisherSources: String,
    private val date: String,
    /** `owners/asns.tsv`: the company behind each listed network (ADR 0036, decision 4), for an app's own proxy (ADR 0052). */
    asns: String = "",
) {
    /** Each listed network's entity, by AS number. */
    private val networks: Map<Long, String> = asns.lineSequence()
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .map { it.split('\t') }
        .filter { it.size >= 2 }
        .mapNotNull { columns -> columns[0].toLongOrNull()?.let { it to columns[1] } }
        .toMap()

    /** The company group of the network of AS [asn], or null where the owners' table lists none. */
    fun groupOfAsn(asn: Long): String? = networks[asn]?.let { owners.group(it, date) }

    /** The company group of a host [name], by the entity whose own domain holds it, or null where none does. */
    fun groupOfHost(name: String): String? {
        val host = name.lowercase().removeSuffix(".")
        val entity = domains.firstOrNull { (domain, _) -> host == domain || host.endsWith(".$domain") }?.second
        return entity?.let { owners.group(it, date) }
    }

    /** Each entity's own domains: the hosts of the asset-links files the owners' table reads, without `www.`. */
    private val domains: List<Pair<String, String>> = publisherSources.lineSequence()
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .map { it.split('\t') }
        .filter { it.size >= 3 && it[1] == "asset-links" }
        .mapNotNull { columns -> host(columns[2])?.let { it to columns[0] } }
        .toList()

    /** The company group of a tracker by its [website], or null where no entity's own domain holds it. */
    fun groupOfWebsite(website: String): String? {
        val host = host(website) ?: return null
        val entity = domains.firstOrNull { (domain, _) -> host == domain || host.endsWith(".$domain") }?.second
        return entity?.let { owners.group(it, date) }
    }

    /**
     * The company group of an app by its packages and their signing: the group of the publishers the table
     * records for them, where they agree; null where it records none, or they lead to different groups.
     */
    fun groupOfApp(packages: List<Pair<String, AppSigning?>>): String? {
        val groups = packages.mapNotNull { (name, signing) -> owners.publisher(name, signing)?.let { owners.group(it, date) } }.toSet()
        return groups.singleOrNull()
    }

    /** A company group's name, or its id where the table holds none. */
    fun name(group: String): String = owners.name(group) ?: group

    private companion object {
        fun host(url: String): String? = try {
            URI(url).host?.lowercase()?.removePrefix("www.")
        } catch (e: URISyntaxException) {
            null
        }
    }
}
