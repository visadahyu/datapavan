package org.visadahyu.datapavan.ui

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.BuildConfig

/**
 * The licence screen's lists (W7, part 2) against the repository's own files, as the APK carries them: every line of
 * the native libraries' lists reads, every part has a text the APK carries, and every crate's own text is found.
 */
class LicenceListTest {
    private val carried = BuildConfig.LICENCE_FILES.split(',')

    /** A file the APK carries under assets/licences/, from the repository: licences/, or NOTICE and LICENSE at its root. */
    private fun repository(file: String): File = File("../../licences", file).takeIf { it.isFile } ?: File("../..", file)

    @Test
    fun `the files the build names are the repository's`() {
        assertTrue(carried.containsAll(listOf("NOTICE", LicenceList.LICENSE, "native-core.txt", LicenceList.JVM_TABLE)))
        assertEquals(BuildConfig.ADVANCED, "native-network.txt" in carried)
        assertEquals(BuildConfig.ADVANCED, "MPL-2.0.txt" in carried && "gotatun-BSD-3-Clause.txt" in carried)
        for (file in carried) assertTrue("$file is not in the repository", repository(file).isFile)
    }

    @Test
    fun `every crate of the native libraries reads, with a text the APK carries`() {
        for (file in carried.filter { it.startsWith("native-") }) {
            val content = repository(file).readText()
            val crates = LicenceList.crates(file, content)
            assertEquals("lines of $file that do not read", emptyList<String>(), crates.unread)
            assertEquals(content.lines().takeWhile { !it.startsWith("====") }.count { it.startsWith("- ") }, crates.crates.size)
            assertTrue(crates.library!!.startsWith("libdatapavan"))
            val paragraphs = LicenceList.paragraphs(content)
            for (crate in crates.crates) {
                assertTrue(crate.licence.isNotBlank())
                for (text in crate.texts) {
                    assertTrue("${crate.name}'s text ${text.file} is not one the APK carries", text.file in carried)
                    // A crate's own text is found where the screen opens it: the block that names it as a carrier.
                    if (text.anchor != null) {
                        val at = LicenceList.anchorIn(paragraphs, text.anchor)
                        assertTrue("${crate.name} ${crate.version} has no text of its own in $file", at > 0)
                        assertTrue(paragraphs[at].lines().any { it.startsWith("Carried by: ") && text.anchor in it })
                    }
                }
            }
        }
    }

    @Test
    fun `gotatun opens the repository's texts, a crate taken under Apache-2_0 opens LICENSE`() {
        val network = LicenceList.crates("native-network.txt", File("../../licences/native-network.txt").readText())
        val gotatun = network.crates.single { it.name == "gotatun" }
        assertEquals("MPL-2.0", gotatun.licence)
        assertEquals(listOf("MPL-2.0.txt", "gotatun-BSD-3-Clause.txt"), gotatun.texts.map { it.file })
        assertTrue(gotatun.texts.all { it.anchor == null })
        val jni = network.crates.single { it.name == "jni" }
        assertEquals(listOf(LicenceList.Text(LicenceList.LICENSE)), jni.texts)
        val adler = network.crates.single { it.name == "adler2" }
        assertEquals(listOf(LicenceList.Text("native-network.txt", "adler2 2.0.1 (")), adler.texts)
    }

    @Test
    fun `a line that does not read is kept, not dropped`() {
        val crates = LicenceList.crates("native-x.txt", "The crates inside libx.so, here\n\n- good 1.0.0: MIT\n- bad line\n- odd 1.0: \n\n====\nCarried by: good 1.0.0 (LICENSE)\n====\n\ntext\n")
        assertEquals("libx.so", crates.library)
        assertEquals(listOf("good"), crates.crates.map { it.name })
        assertEquals(listOf("- bad line", "- odd 1.0: "), crates.unread)
    }

    @Test
    fun `an anchor matches its carrier, not a longer name or version`() {
        val paragraphs = LicenceList.paragraphs("head\n\n====\nCarried by: xaes 0.9.4 (L); aes 0.9.40 (L)\n====\n\none\n\n====\nCarried by: x 1 (L); aes 0.9.4 (L)\n====\n\ntwo\n")
        assertEquals(3, LicenceList.anchorIn(paragraphs, "aes 0.9.4 ("))
        assertEquals(0, LicenceList.anchorIn(paragraphs, "absent 1 ("))
        assertEquals(0, LicenceList.anchorIn(paragraphs, null))
    }

    @Test
    fun `the table of Java and Kotlin libraries reads, each with a text the APK carries`() {
        val rows = LicenceList.jvmRows(File("../../licences/jvm-components.tsv").readText())
        assertTrue(rows.isNotEmpty())
        for (row in rows) {
            assertTrue(row.component.texts.single().file in carried)
            assertTrue(row.component.licence.isNotBlank())
        }
        val edition = LicenceList.edition(BuildConfig.ADVANCED, BuildConfig.PLAY)
        assertTrue(LicenceList.jvm(File("../../licences/jvm-components.tsv").readText(), edition).any { it.name == "Kotlin standard library" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a row of the table with an unknown edition is refused`() {
        LicenceList.jvmRows("a.b\tName\tMIT\tpro\tLICENSE\n")
    }

    @Test
    fun `Cloudflare's text is GotaTun's LICENSE-CLOUDFLARE at v0_10_3, byte for byte`() {
        val content = File("../../licences/gotatun-BSD-3-Clause.txt").readBytes()
        val separator = ("-".repeat(114) + "\n\n").toByteArray()
        val at = content.indices.first { i -> separator.indices.all { content.getOrNull(i + it) == separator[it] } } + separator.size
        val digest = MessageDigest.getInstance("SHA-256").digest(content.copyOfRange(at, content.size))
        assertEquals("6dbef24708bad8c727bd80cca58ba8aa1637cdcb2cc6e9a31ea49235717e9391", digest.joinToString("") { "%02x".format(it) })
    }
}
