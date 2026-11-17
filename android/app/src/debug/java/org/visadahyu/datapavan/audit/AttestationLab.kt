package org.visadahyu.datapavan.audit

import android.content.Context
import android.util.Log
import java.io.File
import java.util.Base64

/**
 * Debug builds only (ADR 0040, "The lab record"): logs what each hardware check saw, so that a lab run can capture
 * a device's real certificate chain. Release builds have a no-op in its place (src/release), and verifyApkRelease
 * fails if a release APK holds [TAG].
 *
 * Off unless the lab turns it on, so that a debug build given to a tester logs nothing: only while the app's own
 * files hold [SWITCH], which only `adb shell run-as` can put there, and only for a debuggable build.
 *
 * What it logs: the verdict, the chain check's verdict, the security level the parser reads, the chain's length,
 * and each certificate as base64 DER. The certificates hold more than the verdict: the leaf states the phone's
 * bootloader lock state, verified boot state, verified boot key and hash, OS version and patch levels, and the
 * app that asked (its package and the SHA-256 of the certificate that signed it: in a debug build, the developer's
 * own debug key, often shared by all their projects); a chain from Remote Key Provisioning carries an
 * intermediate issued for the phone's current attestation key (O=TEE, CN=a serial), which links captures while
 * that key lives; and a factory-provisioned intermediate may name a serial number of the batch or the unit. So
 * a chain becomes a test vector only from a lab device, from a build signed with a throwaway key.
 *
 * Capture: `adb shell run-as <package> touch files/attestation-lab`, run the audit, then
 * `adb logcat -d -s DatapavanAttestationLab:I | scripts/attestation-chain-from-logcat.py > chain.pem`, and
 * `adb shell run-as <package> rm files/attestation-lab`.
 */
object AttestationLab {
    /** The logcat tag; build.gradle.kts names it too, to keep it out of release APKs. */
    const val TAG = "DatapavanAttestationLab"

    /** The file, in the app's files directory, whose presence turns the record on. */
    const val SWITCH = "attestation-lab"

    /** Under logcat's limit of about 4,000 bytes for one message. */
    private const val PART = 3000

    /** The record for the check, to logcat, or nothing while the lab has not turned it on. */
    fun recorder(context: Context): (AttestationSeen) -> Unit = recorder(context.filesDir) { Log.i(TAG, it) }

    /** The record that writes each line to [log] while [files] holds [SWITCH], or nothing. */
    fun recorder(files: File, log: (String) -> Unit): (AttestationSeen) -> Unit =
        if (File(files, SWITCH).isFile) { seen -> lines(seen).forEach(log) } else { _ -> }

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
