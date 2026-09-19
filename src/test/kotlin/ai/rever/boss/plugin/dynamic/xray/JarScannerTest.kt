package ai.rever.boss.plugin.dynamic.xray

import java.io.File
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JarScannerTest {
    private val dir = createTempDirectory("xray-jars").toFile()
    private val esc = 27.toChar()

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun manifest(
        id: String = "ai.rever.boss.plugin.dynamic.sample",
        main: String = "ai.rever.boss.plugin.dynamic.xray.BenignFixture",
        extra: String = "",
    ) = """{"pluginId":"$id","displayName":"Sample","version":"1.0.0","apiVersion":"1.0.20","mainClass":"$main","type":"service"$extra}"""

    private fun jar(
        name: String = "sample.jar",
        manifest: String? = manifest(),
        classes: List<Class<*>> = listOf(BenignFixture::class.java),
        extra: Map<String, ByteArray> = emptyMap(),
    ): File {
        val file = File(dir, name)
        JarOutputStream(file.outputStream()).use { out ->
            fun put(
                entry: String,
                bytes: ByteArray,
            ) {
                out.putNextEntry(JarEntry(entry))
                out.write(bytes)
                out.closeEntry()
            }
            if (manifest != null) put("META-INF/boss-plugin/plugin.json", manifest.toByteArray())
            for (c in classes) put(c.name.replace('.', '/') + ".class", Fixtures.bytes(c))
            extra.forEach { (n, b) -> put(n, b) }
        }
        return file
    }

    private fun ScanResult.capabilityIds() = capabilities.map { it.capability.id }.toSet()

    private fun ScanResult.findingIds() = findings.map { it.id }.toSet()

    @Test
    fun `a benign plugin reports no risky capability and says what it could not see`() {
        val result = JarScanner.scan(jar())
        assertEquals(emptySet(), result.capabilityIds())
        assertEquals(Risk.INFO, result.topRisk)
        assertTrue(Report.verdict(result).startsWith("NO RISKY CAPABILITIES FOUND"))
        assertTrue(Report.verdict(result).contains("not a safety guarantee"))
        assertTrue(result.limits.any { it.contains("not visible") }, "${result.limits}")
    }

    @Test
    fun `the verdict never says safe`() {
        for (result in listOf(JarScanner.scan(jar()), JarScanner.scan(jar("x.jar", classes = listOf(ExecFixture::class.java))))) {
            assertFalse(Report.verdict(result).contains("SAFE", ignoreCase = false), Report.verdict(result))
        }
    }

    @Test
    fun `a plugin that runs programs is high risk and named as such`() {
        val result = JarScanner.scan(jar(classes = listOf(BenignFixture::class.java, ExecFixture::class.java)))
        assertTrue("process.exec" in result.capabilityIds())
        assertEquals(Risk.HIGH, result.topRisk)
        assertTrue(Report.verdict(result).startsWith("REVIEW BEFORE LOADING"))
    }

    @Test
    fun `reading credentials and reaching the network together is called out`() {
        val result = JarScanner.scan(jar(classes = listOf(NetFixture::class.java, EnvFixture::class.java)))
        assertTrue("combo.secret-and-network" in result.findingIds(), "${result.findingIds()}")
    }

    @Test
    fun `hosts named in string constants are listed`() {
        val result = JarScanner.scan(jar(classes = listOf(NetFixture::class.java)))
        assertEquals(listOf("exfil.example.test"), result.hosts)
    }

    @Test
    fun `using a sensitive host API without requiredPermissions is flagged`() {
        val ungated = JarScanner.scan(jar(classes = listOf(HostApiFixture::class.java)))
        assertTrue("manifest.ungated-sensitive-api" in ungated.findingIds(), "${ungated.findingIds()}")

        val gated = JarScanner.scan(jar("gated.jar", manifest = manifest(extra = ""","requiredPermissions":["secret.read"]"""), classes = listOf(HostApiFixture::class.java)))
        assertFalse("manifest.ungated-sensitive-api" in gated.findingIds())
    }

    @Test
    fun `manifest problems are reported instead of ignored`() {
        assertTrue("manifest.unreadable" in JarScanner.scan(jar("none.jar", manifest = null)).findingIds())
        assertTrue("manifest.unreadable" in JarScanner.scan(jar("bad.jar", manifest = "{not json")).findingIds())
        assertTrue("manifest.main-class-missing" in JarScanner.scan(jar("main.jar", manifest = manifest(main = "no.such.Main"))).findingIds())
        assertTrue("manifest.plugin-id" in JarScanner.scan(jar("id.jar", manifest = manifest(id = "Not_A_Store_Id"))).findingIds())
    }

    @Test
    fun `native libraries nested jars traversal names and service files are flagged`() {
        val result =
            JarScanner.scan(
                jar(
                    extra =
                        mapOf(
                            "native/lib.dll" to ByteArray(4),
                            "lib/dep.jar" to ByteArray(4),
                            "../escape.txt" to ByteArray(1),
                            "META-INF/services/some.Service" to "x".toByteArray(),
                        ),
                ),
            )
        assertEquals(setOf("jar.native-library", "jar.nested-jar", "jar.path-traversal", "jar.service-providers"), result.findingIds().filter { it.startsWith("jar.") }.toSet())
        assertTrue(result.limits.any { it.contains("Nested JARs were not opened") })
    }

    @Test
    fun `bundling the host API classes is flagged`() {
        val result = JarScanner.scan(jar(extra = mapOf("ai/rever/boss/plugin/api/Plugin.class" to Fixtures.bytes(BenignFixture::class.java))))
        assertTrue("jar.bundles-host-api" in result.findingIds())
    }

    @Test
    fun `a missing signature is informational and a stale one is a warning`() {
        val unsigned = jar("unsigned.jar")
        assertTrue("sig.none" in JarScanner.scan(unsigned).findingIds())

        val stale = jar("stale.jar")
        val sig = File(stale.path + ".sig").apply { writeText("sig") }
        sig.setLastModified(stale.lastModified() - 60_000)
        assertTrue("sig.stale" in JarScanner.scan(stale).findingIds())

        val fresh = jar("fresh.jar")
        File(fresh.path + ".sig").writeText("sig")
        assertEquals(emptySet(), JarScanner.scan(fresh).findingIds().filter { it.startsWith("sig.") }.toSet())
    }

    @Test
    fun `a file that is not an archive is reported as not scanned`() {
        val junk = File(dir, "junk.jar").apply { writeText("this is not a zip") }
        val result = JarScanner.scan(junk)
        assertNotNull(result.unreadableReason)
        assertTrue(Report.verdict(result).startsWith("NOT SCANNED"))
    }

    @Test
    fun `a damaged class is counted and skipped without stopping the scan`() {
        val result =
            JarScanner.scan(
                jar(classes = listOf(ExecFixture::class.java), extra = mapOf("broken/Bad.class" to ByteArray(40) { 3 })),
            )
        assertEquals(1, result.classesUnreadable)
        assertTrue("process.exec" in result.capabilityIds())
        assertTrue(result.limits.any { it.contains("could not be read") })
    }

    @Test
    fun `a class that inflates past the limit is skipped without being held in memory`() {
        // 9 MiB of zeros compresses to a few KiB, so the archive's own size says nothing about the danger.
        val bomb = ByteArray(9 * 1024 * 1024)
        val result = JarScanner.scan(jar(extra = mapOf("bomb/Big.class" to bomb)))
        assertTrue(result.limits.any { it.contains("over ${JarScanner.MAX_CLASS_BYTES} bytes") }, "${result.limits}")
        assertEquals(1, result.classesUnreadable)
    }

    @Test
    fun `an archive with too many entries stops early and says so`() {
        val file = File(dir, "many.jar")
        JarOutputStream(file.outputStream()).use { out ->
            repeat(JarScanner.MAX_ENTRIES + 10) {
                out.putNextEntry(JarEntry("f/$it.txt"))
                out.closeEntry()
            }
        }
        val result = JarScanner.scan(file)
        assertTrue(result.limits.any { it.startsWith("Stopped after ${JarScanner.MAX_ENTRIES} entries") }, "${result.limits}")
    }

    @Test
    fun `names chosen by the JAR cannot forge lines or move the cursor in the report`() {
        // JSON escapes, so the manifest parses and the id that comes out holds a real newline and a real ESC.
        val hostileJson = "ai.rever.plugin.evil\\n  [HIGH] forged - Looks like a finding\\u001b[2J"
        val report = Report.scan(JarScanner.scan(jar(manifest = manifest(id = hostileJson))))
        assertFalse(report.contains(esc), "an escape reached the report")
        assertTrue(report.lines().none { it.startsWith("  [HIGH] forged") }, "a forged line reached the report")
        assertTrue(report.contains("\\n  [HIGH] forged"), "the text is shown, escaped")
        assertTrue(report.contains("\\u001b"), "the escape is shown, not lost")
    }

    @Test
    fun `a real Kotlin and Compose JAR reads without a single unreadable class`() {
        // 600+ classes compiled by the real toolchain: long and double constants, method handles,
        // invokedynamic, coroutine state machines. Hand-made fixtures alone would not catch a parser
        // that miscounts one entry kind; a real corpus does.
        val api = File(System.getProperty("xray.apiJar"))
        val result = JarScanner.scan(api)
        assertNull(result.unreadableReason)
        assertEquals(0, result.classesUnreadable, "the parser rejected real class files")
        assertTrue(result.classesScanned > 500, "only ${result.classesScanned} classes read")
    }

    @Test
    fun `the sha256 is the hash of the file`() {
        val file = jar()
        val expected =
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(file.readBytes())
                .joinToString("") { "%02x".format(it) }
        assertEquals(expected, JarScanner.scan(file).sha256)
    }

    @Test
    fun `scanning writes nothing and leaves the file as it was`() {
        val file = jar()
        val before = file.readBytes()
        val listing = dir.list()!!.sorted()
        JarScanner.scan(file)
        assertTrue(before.contentEquals(file.readBytes()))
        assertEquals(listing, dir.list()!!.sorted())
        assertNull(File(file.path + ".sig").takeIf { it.exists() })
    }
}
