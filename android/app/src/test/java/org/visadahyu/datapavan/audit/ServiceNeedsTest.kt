package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ServiceNeedsTest {
    private val services = """
        # comment
        gms	Google Play services	com.google.android.gms
        store	Google Play Store	com.android.vending
        hms	HMS Core	com.huawei.hwid,com.huawei.hwid.tv
        broken
    """.trimIndent()

    private fun row(key: String, needs: String, grade: Int, identifier: String = "com.example.$key.Client") =
        listOf(key, needs, "class", identifier, grade, "https://example.org", "https://example.org/a.aar", "a".repeat(64), "2026-10-30").joinToString("\t")

    private val capabilities = listOf(
        "# comment",
        row("ad-id", "gms", 1),
        row("push", "gms,store", 1),
        row("queued", "hms", 4),
        row("unknown-service", "nothing", 1),
        "short\trow",
    ).joinToString("\n")

    private val signers = listOf(
        "gms\t${"1".repeat(64)}\t1\turl\t${"a".repeat(64)}\t2026-10-30",
        "gms\t${"2".repeat(64)}\t1\turl\t${"a".repeat(64)}\t2026-10-30",
        "gms\tnot-a-hash\t1\turl\t${"a".repeat(64)}\t2026-10-30",
        "other\t${"3".repeat(64)}\t1\turl\t${"a".repeat(64)}\t2026-10-30",
    ).joinToString("\n")

    private val needs = ServiceNeeds.parse(services, capabilities, signers)

    @Test
    fun keepsOnlyProvenCapabilitiesOfKnownServices() {
        assertEquals(listOf("ad-id", "push"), needs.capabilities.map { it.key })
        assertEquals(listOf(ServiceNeeds.FIRST_ID, ServiceNeeds.FIRST_ID + 1), needs.capabilities.map { it.id })
        assertEquals(listOf("gms", "store"), needs.byId(ServiceNeeds.FIRST_ID + 1)?.services)
        assertNull(needs.byId(ServiceNeeds.FIRST_ID + 2))
        assertEquals(setOf("gms", "store", "hms"), needs.services.keys)
        assertEquals(listOf("com.huawei.hwid", "com.huawei.hwid.tv"), needs.services.getValue("hms").packages)
        assertEquals(mapOf("gms" to setOf("1".repeat(64), "2".repeat(64))), needs.signers)
    }

    @Test
    fun addsTheirClassesToTheScannerSignatures() {
        assertEquals(
            "${ServiceNeeds.FIRST_ID}\tad-id\t\t\tcom.example.ad-id.Client\t\n${ServiceNeeds.FIRST_ID + 1}\tpush\t\t\tcom.example.push.Client\t",
            needs.signatureTsv(),
        )
    }

    @Test
    fun aCapabilityIsUnavailableOnlyWhenAServiceItNeedsIsAbsent() {
        val push = needs.byId(ServiceNeeds.FIRST_ID + 1)!!
        val genuine = mapOf("gms" to ServiceState.GENUINE, "store" to ServiceState.GENUINE)
        assertFalse(needs.unavailable(push, genuine))
        assertFalse(needs.unavailable(push, genuine + ("store" to ServiceState.SUBSTITUTE)))
        assertTrue(needs.unavailable(push, genuine + ("store" to ServiceState.ABSENT)))
        // A service the phone was not checked for gives no label.
        assertFalse(needs.unavailable(push, emptyMap()))
    }

    private val google = "1".repeat(64)
    private fun pkg(enabled: Boolean = true, signer: String? = google, microg: Boolean = false) =
        ServicePackage(enabled, signedBy = { it == signer }, microgMarkers = microg)

    @Test
    fun judgesAServiceFromItsPackages() {
        val signers = setOf(google)
        assertEquals(ServiceState.ABSENT, ServiceCheck.state(listOf(null), signers))
        assertEquals(ServiceState.ABSENT, ServiceCheck.state(listOf(pkg(enabled = false)), signers))
        assertEquals(ServiceState.GENUINE, ServiceCheck.state(listOf(pkg()), signers))
        assertEquals(ServiceState.SUBSTITUTE, ServiceCheck.state(listOf(pkg(signer = "9".repeat(64))), signers))
        // microG may present Google's certificate; its own marks win.
        assertEquals(ServiceState.SUBSTITUTE, ServiceCheck.state(listOf(pkg(microg = true)), signers))
        // Without a list of signers nothing is genuine, but an installed package is still present.
        assertEquals(ServiceState.SUBSTITUTE, ServiceCheck.state(listOf(pkg()), emptySet()))
        // Any of a service's packages is enough.
        assertEquals(ServiceState.GENUINE, ServiceCheck.state(listOf(null, pkg(enabled = false), pkg()), signers))
    }

    @Test
    fun readsTheShippedData() {
        val data = File("../../data/sdk-needs")
        val shipped = ServiceNeeds.parse(
            File(data, "services.tsv").readText(),
            File(data, "capabilities.tsv").readText(),
            File(data, "signers.tsv").readText(),
        )
        assertTrue(shipped.capabilities.any { it.key == "google-ad-id" && it.services == listOf("google-play-services") })
        assertTrue(shipped.signers.getValue("google-play-services").contains("f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"))
    }
}
