package org.visadahyu.datapavan.audit

import android.content.pm.PackageInfo
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * The signing certificates of an installed app, as SHA-256 of each certificate the way apksigner
 * prints it, for matching against ADR 0018's list. [info] must be read with
 * `PackageManager.GET_SIGNING_CERTIFICATES`. Shared by the audit app and Watch (android/shared).
 */
fun appSigning(info: PackageInfo): AppSigning? {
    val signing = info.signingInfo ?: return null
    val current = signing.apkContentsSigners.orEmpty().toList()
    val history = if (signing.hasMultipleSigners()) current else signing.signingCertificateHistory.orEmpty().toList()
    val debug = current.any { signature ->
        try {
            // A factory per call: callers read several apps at once.
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(signature.toByteArray().inputStream()) as X509Certificate
            certificate.subjectX500Principal.name.contains("CN=Android Debug")
        } catch (_: CertificateException) {
            false
        }
    }
    return AppSigning(current.map { sha256(it.toByteArray()) }, history.map { sha256(it.toByteArray()) }, debug)
}

private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(Locale.ROOT, it) }
