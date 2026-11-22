package org.visadahyu.datapavan.watch.dns

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The certificates Watch's encrypted resolver accepts (W8, part 1, ADR 0042, "How it is built", point 1): chains to
 * the roots Android ships, never to a certificate authority the user or an administrator installed, which could be
 * a network's or an abuser's, and, where the dataset gives pins for an endpoint, a chain that holds one of them.
 *
 * Android keeps its roots in `AndroidCAStore` under aliases that begin `system:` and the user's under `user:`; only
 * the first are taken. Debug builds may add the DNS lab's test root ([extra]), never release builds.
 */
object SystemTrust {
    /** The trust manager over Android's own roots, and [extra] (debug builds' lab root) beside them. */
    fun android(extra: List<X509Certificate> = emptyList()): X509TrustManager {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        return manager(systemRoots(store) + extra)
    }

    /** The roots of [store] whose alias says Android ships them. */
    fun systemRoots(store: KeyStore): List<X509Certificate> =
        store.aliases().toList().filter { isSystem(it) }.mapNotNull { store.getCertificate(it) as? X509Certificate }

    /** Whether an alias of `AndroidCAStore` names a root Android ships (not one the user or an administrator added). */
    fun isSystem(alias: String): Boolean = alias.startsWith("system:")

    /** A trust manager over exactly [roots]. */
    fun manager(roots: List<X509Certificate>): X509TrustManager {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        roots.forEachIndexed { i, root -> store.setCertificateEntry("root-$i", root) }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(store)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    /** The pin of a certificate: `sha256/` and the Base64 of the SHA-256 of its public key (SPKI), as OkHttp writes it. */
    fun pin(certificate: X509Certificate): String =
        "sha256/" + java.util.Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded))

    /** Fails unless [pins] is empty or one certificate of [chain] holds one of them. */
    fun checkPins(chain: List<X509Certificate>, pins: List<String>) {
        if (pins.isEmpty()) return
        if (chain.none { pin(it) in pins }) throw CertificateException("no certificate of the chain matches the endpoint's pins")
    }
}
