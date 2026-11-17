package org.visadahyu.datapavan.audit

import android.util.Log
import java.util.Base64

/**
 * Debug builds only (ADR 0040, "The lab record"): logs what each hardware check saw, so that a lab run can capture
 * a device's real certificate chain. Release builds have a no-op in its place (src/release), and verifyApkRelease
 * fails if a release APK holds [TAG].
 *
 * It logs the verdict, the chain check's verdict, the security level the parser reads, the chain's length, and
 * each certificate as base64 DER: public data, and nothing else of the phone. A chain from Remote Key Provisioning
 * carries a certificate issued for this phone's current attestation key, so a chain is published as a test vector
 * only from lab devices.
 *
 * Capture: `adb logcat -d -s DatapavanAttestationLab:I | scripts/attestation-chain-from-logcat.py > chain.pem`.
 */
object AttestationLab {
    /** The logcat tag; build.gradle.kts names it too, to keep it out of release APKs. */
    const val TAG = "DatapavanAttestationLab"

    /** Under logcat's limit of about 4,000 bytes for one message. */
    private const val PART = 3000

    fun record(seen: AttestationSeen) = lines(seen).forEach { Log.i(TAG, it) }

    /** The lines logged for [seen]: a summary, each certificate in parts, and an end mark. */
    fun lines(seen: AttestationSeen): List<String> = buildList {
        val count = seen.chain.size
        add("check verdict=${seen.verdict} chain=${seen.chainTrust ?: "-"} level=${seen.securityLevel ?: "-"} certificates=$count")
        seen.chain.forEachIndexed { index, certificate ->
            val parts = Base64.getEncoder().encodeToString(certificate.encoded).chunked(PART)
            parts.forEachIndexed { part, text -> add("certificate ${index + 1}/$count part ${part + 1}/${parts.size} $text") }
        }
        add("end")
    }
}
