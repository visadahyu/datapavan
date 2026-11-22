package org.visadahyu.datapavan.watch.blocking

/**
 * Which apps tracker blocking covers (W8, part 3a; ADR 0053, point 5 of the brief), as pure rules the JVM tests hold:
 * the apps the user installed, by UID, and nothing that came with the phone. Never Watch itself, never Android's own
 * UIDs (below 10000, the system's 1000 among them), never Google Play services, never the user's circumvention tool,
 * whose connections show cover names that may be any popular host, and no browser unless the user includes them: a
 * browser opens any website, whose hosts are the user's choice. Who publishes an app plays no part: an app of the
 * tracker's own company is covered as any other (decision 2).
 */
object Coverage {
    /** `android.os.Process.FIRST_APPLICATION_UID`: UIDs below it are Android's own. */
    const val FIRST_APP_UID = 10_000

    /** Google Play services, whose UID is never covered (Firebase may send through it: a limit the lab measures). */
    const val PLAY_SERVICES = "com.google.android.gms"

    /**
     * The address a browser is asked to open, to tell browsers ([browsers]): a host no app can claim, under `.invalid`
     * (RFC 2606), so that an app that opens only its own site's links does not answer it.
     */
    const val BROWSER_PROBE = "https://example.invalid/"

    /**
     * An installed package: its [uid], its name, and whether it came with the phone ([system]: `FLAG_SYSTEM`, or
     * `FLAG_UPDATED_SYSTEM_APP` for one updated since).
     */
    data class App(val uid: Int, val packageName: String, val system: Boolean)

    /**
     * The UIDs covered among [apps]: those of packages the user installed, [self] (Watch's own), [playServices] and
     * [tool] (the user's tool's, while one is known) left out, and the [browsers] unless [includeBrowsers]. Packages that
     * share a UID share its traffic, so a UID is covered only where every package that holds it may be.
     */
    fun covered(
        apps: List<App>,
        self: Int,
        playServices: Int?,
        tool: Int?,
        browsers: Set<String>,
        includeBrowsers: Boolean,
    ): Set<Int> = apps.groupBy { it.uid }.filter { (uid, packages) ->
        uid >= FIRST_APP_UID && uid != self && uid != playServices && uid != tool &&
            packages.none { it.system || it.packageName == PLAY_SERVICES || (!includeBrowsers && it.packageName in browsers) }
    }.keys.toSortedSet()

    /**
     * The browsers among the apps that answered [BROWSER_PROBE] (`ACTION_VIEW`, `CATEGORY_BROWSABLE`, every match and
     * its filter): each answer as its package and how many authorities (hosts) its filter names, null where Android gave
     * no filter. Only a filter that names no host counts, so that an app whose App Links claim its own site's hosts, or
     * one claiming any host by a pattern, is not taken for a browser.
     */
    fun browsers(answers: List<Pair<String, Int?>>): Set<String> = answers.filter { it.second == 0 }.map { it.first }.toSortedSet()
}
