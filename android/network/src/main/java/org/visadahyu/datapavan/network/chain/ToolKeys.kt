package org.visadahyu.datapavan.network.chain

import android.content.Context
import android.content.pm.PackageManager
import org.visadahyu.datapavan.audit.AppSigners
import org.visadahyu.datapavan.audit.SignatureVerdict
import org.visadahyu.datapavan.audit.appSigning
import java.io.IOException
import java.time.LocalDate
import java.time.format.DateTimeParseException

/**
 * What the found tool's signing key says about this copy (W6), judged by the audit app's own rules
 * (ADR 0018, android/shared): signed with a key recorded for the tool, with a key not recorded yet
 * (no claim: most such copies come from a store whose key is not known), or with positive evidence of a
 * modified copy. The keys are the build's copy of data/app-signers. Blocking: call it off the main thread.
 */
object ToolKeys {
    /** Where the build puts data/app-signers' SOURCE, whose `retrieved:` date says how old the keys are. */
    private const val SOURCE = "app-signers/SOURCE"

    /** Keys older than this no longer prove that another key is a modification: keys change. */
    private const val STALE_MONTHS = 6L

    /** The verdict on the installed copy of [packageName], or null when nothing can be said. */
    fun verdict(context: Context, packageName: String, today: LocalDate = LocalDate.now()): SignatureVerdict? =
        judge(context, today)?.invoke(packageName)

    /**
     * A judge of many installed packages, each as [verdict] judges it, with the keys read and parsed once for all of
     * them (the proxy record's unit B, B6: the tools' UIDs judge some sixty packages); null when the keys cannot be
     * read. Blocking, the judge too: call both off the main thread.
     */
    fun judge(context: Context, today: LocalDate = LocalDate.now()): ((String) -> SignatureVerdict?)? {
        val signers = try {
            AppSigners.parse(asset(context, AppSigners.APPS_PATH), asset(context, AppSigners.SIGNERS_PATH))
        } catch (e: IOException) {
            return null
        }
        val fresh = try {
            fresh(asset(context, SOURCE), today)
        } catch (e: IOException) {
            false
        }
        return { packageName ->
            val info = try {
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
            info?.let { signers.judge(packageName, appSigning(it), fresh) }
        }
    }

    /** Whether the keys in [source] (data/app-signers' SOURCE) were read less than six months before [today]. */
    fun fresh(source: String, today: LocalDate): Boolean {
        val date = source.lineSequence().firstOrNull { it.startsWith("retrieved:") }?.substringAfter(':')?.trim()
            ?: return false
        return try {
            !LocalDate.parse(date).plusMonths(STALE_MONTHS).isBefore(today)
        } catch (e: DateTimeParseException) {
            false
        }
    }

    private fun asset(context: Context, path: String): String =
        context.assets.open(path).bufferedReader().use { it.readText() }
}
