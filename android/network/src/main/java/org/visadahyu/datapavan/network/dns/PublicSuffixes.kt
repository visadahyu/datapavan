package org.visadahyu.datapavan.network.dns

/**
 * The ICANN section of the public suffix list, as the data pack carries it (`public-suffix/icann.dat`, W8's fix round,
 * review S-C1): the domains under which anyone may register a name (`com`, `co.uk`, `*.ck` but not `www.ck`). A
 * network's search domain that is one of them is never the network's own, so the network part ignores it
 * ([SearchDomains]).
 */
class PublicSuffixes private constructor(private val rules: Set<String>) {
    /** Whether the list holds anything: without it, the network part accepts no search domain. */
    val known: Boolean get() = rules.isNotEmpty()

    /**
     * Whether [domain] (lower case, ASCII, no final dot) is a public suffix: a rule names it, or a wildcard names its
     * parent and no exception names it, or it is a single label (the list's implicit rule `*`).
     */
    fun isSuffix(domain: String): Boolean {
        if ('.' !in domain) return true
        if (domain in rules) return true
        if ("!$domain" in rules) return false
        return "*.${domain.substringAfter('.')}" in rules
    }

    companion object {
        /** Reads the file: one rule per line, comment lines (`//`) and blank lines left out. */
        fun parse(text: String): PublicSuffixes = PublicSuffixes(
            text.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("//") }
                .map { it.lowercase() }
                .toHashSet(),
        )
    }
}

/** Which of a network's search domains the network part takes as the network's own (W8's fix round, review S-C1). */
object SearchDomains {
    /** The network part keeps at most this many, as the engine does. */
    private const val MOST = 16

    /**
     * The domains of [domains] (Android's `LinkProperties.getDomains`, by spaces or commas) that may be the
     * network's own: not a single label, not a public suffix of [suffixes], each once, lower case, at most [MOST];
     * none at all without the list, since then the network part cannot tell.
     */
    fun accepted(domains: String, suffixes: PublicSuffixes): String {
        if (!suffixes.known) return ""
        return domains.split(' ', ',')
            .map { it.trim().trimEnd('.').lowercase() }
            .filter { it.isNotEmpty() && it.all { c -> c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '.' } }
            .filter { !it.startsWith('.') && !it.contains("..") && !suffixes.isSuffix(it) }
            .distinct()
            .take(MOST)
            .joinToString(" ")
    }
}
