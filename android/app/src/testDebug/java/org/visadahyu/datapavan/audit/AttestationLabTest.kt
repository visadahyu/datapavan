package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * The debug builds' lab record (src/debug): off unless the lab turns it on; its lines carry the whole chain, each
 * under logcat's limit; and scripts/attestation-chain-from-logcat.py turns them back into that chain, or fails.
 */
class AttestationLabTest {
    private fun certificates(file: File) = file.inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
    }

    private val pixel3 = certificates(File("../../core/engine/testdata/keyattestation/blueline/sdk28/SB_RSA_NONE.pem"))

    /** Longer, in base64, than one part of a line. */
    private val large = certificates(File(javaClass.getResource("/attestation/synthetic/large-certificate.pem")!!.toURI())).single()

    private val chain = listOf(large) + pixel3

    @Test
    fun `the record is off unless the lab turns it on`() {
        val files = Files.createTempDirectory("lab").toFile()
        val seen = AttestationSeen("GOOGLE_ROOT", AttestationTrust.GOOGLE_ROOT, 2, pixel3)
        val logged = mutableListOf<String>()
        AttestationLab.recorder(files) { logged += it }(seen)
        assertEquals(emptyList<String>(), logged)
        // A directory of that name is not the switch; the file is.
        File(files, AttestationLab.SWITCH).mkdir()
        AttestationLab.recorder(files) { logged += it }(seen)
        assertEquals(emptyList<String>(), logged)
        File(files, AttestationLab.SWITCH).delete()
        File(files, AttestationLab.SWITCH).writeText("")
        AttestationLab.recorder(files) { logged += it }(seen)
        assertEquals(AttestationLab.lines(seen), logged)
        files.deleteRecursively()
    }

    @Test
    fun `the lines carry the verdict and every certificate whole, in parts under logcat's limit`() {
        val lines = AttestationLab.lines(AttestationSeen("GOOGLE_ROOT", AttestationTrust.GOOGLE_ROOT, 2, chain))
        assertEquals("check verdict=GOOGLE_ROOT chain=GOOGLE_ROOT level=2 certificates=${chain.size}", lines.first())
        assertEquals("end", lines.last())
        assertTrue(lines.all { it.toByteArray().size < 4000 })
        assertTrue(Base64.getEncoder().encodeToString(large.encoded).length > 3000)
        val parts = lines.drop(1).dropLast(1).map { it.split(" ") }
        assertEquals(2, parts.count { it[1] == "1/${chain.size}" })
        for ((index, certificate) in chain.withIndex()) {
            val text = parts.filter { it[1] == "${index + 1}/${chain.size}" }.sortedBy { it[3].substringBefore('/').toInt() }
                .joinToString("") { it[4] }
            assertArrayEquals(certificate.encoded, Base64.getDecoder().decode(text))
        }
    }

    @Test
    fun `a failed check without a chain says so`() {
        val lines = AttestationLab.lines(AttestationSeen("failed: FAILED (ProviderException)", null, null, emptyList()))
        assertEquals(listOf("check verdict=failed: FAILED (ProviderException) chain=- level=- certificates=0", "end"), lines)
    }

    /** Runs the capture script on [log], as logcat would print it; its exit status and output. */
    private fun capture(log: List<String>): Pair<Int, String> {
        val process = ProcessBuilder("python3", "-I", "../../scripts/attestation-chain-from-logcat.py")
            .redirectError(ProcessBuilder.Redirect.INHERIT).start()
        process.outputStream.bufferedWriter().use { writer ->
            log.forEach { writer.write("11-17 17:44:51.055  2529  2700 I ${AttestationLab.TAG}: $it\n") }
        }
        val output = process.inputStream.bufferedReader().readText()
        return process.waitFor() to output
    }

    @Test
    fun `the capture script gives back the chain, and fails on a capture that lost any of it`() {
        val lines = AttestationLab.lines(AttestationSeen("GOOGLE_ROOT", AttestationTrust.GOOGLE_ROOT, 2, chain))
        val (status, pem) = capture(lines)
        assertEquals(0, status)
        val back = CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream()).map { it.encoded.toList() }
        assertEquals(chain.map { it.encoded.toList() }, back)
        // A whole certificate lost, one part of one lost, the end lost, or the summary lost: each fails.
        assertNotEquals(0, capture(lines.filterNot { it.startsWith("certificate 2/") }).first)
        assertNotEquals(0, capture(lines.filterNot { it.startsWith("certificate 1/${chain.size} part 2/") }).first)
        assertNotEquals(0, capture(lines.dropLast(1)).first)
        assertNotEquals(0, capture(lines.drop(1)).first)
    }
}
