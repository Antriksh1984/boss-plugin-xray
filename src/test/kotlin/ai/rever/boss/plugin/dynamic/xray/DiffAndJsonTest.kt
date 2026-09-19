package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.McpToolArgs
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DiffAndJsonTest {
    private val dir = createTempDirectory("xray-diff").toFile()

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun jar(
        name: String,
        classes: List<Class<*>>,
        id: String = "ai.rever.boss.plugin.dynamic.sample",
        version: String = "1.0.0",
        permissions: String = "[]",
    ): File {
        val file = File(dir, name)
        JarOutputStream(file.outputStream()).use { out ->
            out.putNextEntry(JarEntry("META-INF/boss-plugin/plugin.json"))
            out.write(
                """{"pluginId":"$id","displayName":"D","version":"$version","apiVersion":"1.0.20","mainClass":"ai.rever.boss.plugin.dynamic.xray.BenignFixture","requiredPermissions":$permissions}"""
                    .toByteArray(),
            )
            out.closeEntry()
            for (c in classes) {
                for (info in Fixtures.withInner(c)) {
                    out.putNextEntry(JarEntry(info.name + ".class"))
                    out.write(Fixtures.bytesOf(info.name))
                    out.closeEntry()
                }
            }
        }
        return file
    }

    private fun diff(
        old: File,
        new: File,
    ) = ScanDiff.of(JarScanner.scan(old), JarScanner.scan(new))

    @Test
    fun `an update that gains capabilities is reported with the risk of what it gained`() {
        val old = jar("old.jar", listOf(BenignFixture::class.java), version = "1.0.0")
        val new = jar("new.jar", listOf(BenignFixture::class.java, ExecFixture::class.java, NetFixture::class.java), version = "1.1.0")

        val d = diff(old, new)

        assertEquals(setOf("process.exec", "net.client"), d.addedCapabilities.map { it.capability.id }.toSet())
        assertEquals(emptyList(), d.removedCapabilities)
        assertEquals(Risk.HIGH, d.addedRisk)
        assertTrue(d.verdict.startsWith("REVIEW BEFORE LOADING"), d.verdict)
        assertEquals(listOf("exfil.example.test"), d.addedHosts)
        val text = DiffReport.text(d)
        assertTrue(text.contains("Capabilities GAINED (2)"), text)
        assertTrue(text.contains("v1.0.0") && text.contains("v1.1.0"), text)
    }

    @Test
    fun `dropping a capability is reported and is not a warning`() {
        val old = jar("old.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val new = jar("new.jar", listOf(BenignFixture::class.java))

        val d = diff(old, new)

        assertEquals(listOf("process.exec"), d.removedCapabilities.map { it.capability.id })
        assertEquals(emptyList(), d.addedCapabilities)
        assertTrue(d.verdict.startsWith("NO NEW CAPABILITIES"), d.verdict)
    }

    @Test
    fun `identical builds have no changes`() {
        val a = jar("a.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val b = jar("b.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val d = diff(a, b)
        assertEquals(emptyList(), d.addedCapabilities)
        assertEquals(emptyList(), d.removedCapabilities)
        assertTrue(d.verdict.startsWith("NO NEW CAPABILITIES"))
    }

    @Test
    fun `moving a call to another class is not a change`() {
        // Compared by capability id: the same capability seen in a different class is the same capability.
        val old = jar("old.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val new = jar("new.jar", listOf(BenignFixture::class.java, WideConstantsFixture::class.java))
        val d = diff(old, new)
        assertEquals(emptyList(), d.addedCapabilities)
        assertEquals(emptyList(), d.removedCapabilities)
    }

    @Test
    fun `permission changes are reported and signature findings are not compared`() {
        val old = jar("old.jar", listOf(BenignFixture::class.java), permissions = """["secret.read"]""")
        File(old.path + ".sig").writeText("sig")
        val new = jar("new.jar", listOf(BenignFixture::class.java), permissions = """["secret.read","role.read"]""")

        val d = diff(old, new)

        assertEquals(listOf("role.read"), d.addedPermissions)
        assertFalse(d.addedFindings.any { it.id.startsWith("sig.") } || d.removedFindings.any { it.id.startsWith("sig.") })
    }

    @Test
    fun `two different plugins are flagged as such`() {
        val a = jar("a.jar", listOf(BenignFixture::class.java), id = "ai.rever.boss.plugin.dynamic.one")
        val b = jar("b.jar", listOf(BenignFixture::class.java), id = "ai.rever.boss.plugin.dynamic.two")
        val d = diff(a, b)
        assertFalse(d.samePlugin)
        assertTrue(DiffReport.text(d).contains("do not declare the same pluginId"))
    }

    @Test
    fun `an unreadable JAR is not compared`() {
        val junk = File(dir, "junk.jar").apply { writeText("not a zip") }
        val good = jar("good.jar", listOf(BenignFixture::class.java))
        assertTrue(diff(junk, good).verdict.startsWith("NOT COMPARED"))
    }

    @Test
    fun `the JSON scan parses back and carries the fields a CI step needs`() {
        val file = jar("j.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val parsed = MiniJson.parse(JsonReport.scan(JarScanner.scan(file))).asObject()!!

        assertEquals("HIGH", parsed["topRisk"])
        assertEquals("ai.rever.boss.plugin.dynamic.sample", parsed["plugin"].asObject()!!["pluginId"])
        val caps = (parsed["capabilities"] as List<*>).map { (it as Map<*, *>)["id"] }
        assertTrue("process.exec" in caps, "$caps")
        assertNotNull(parsed["limits"])
    }

    @Test
    fun `the JSON diff parses back`() {
        val old = jar("old.jar", listOf(BenignFixture::class.java))
        val new = jar("new.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))
        val parsed = MiniJson.parse(JsonReport.diff(diff(old, new))).asObject()!!
        assertEquals("HIGH", parsed["addedRisk"])
        assertEquals(true, parsed["samePlugin"])
        assertEquals(listOf("process.exec"), (parsed["addedCapabilities"] as List<*>).map { (it as Map<*, *>)["id"] })
    }

    @Test
    fun `hostile strings cannot break out of the JSON or reach it as control characters`() {
        val esc = 27.toChar()
        val hostileId = "ai.rever.evil\\\"}],\\n\\u001b[2J\\u202e"
        val file = jar("evil.jar", listOf(BenignFixture::class.java), id = hostileId)
        val text = JsonReport.scan(JarScanner.scan(file))

        val parsed = MiniJson.parse(text).asObject()!! // still valid JSON
        assertTrue((parsed["plugin"].asObject()!!["pluginId"] as String).contains("evil"))
        assertFalse(text.any { it.code < 0x20 && it != '\n' }, "a raw control character reached the JSON")
        assertFalse(text.contains(esc))
        assertFalse(text.contains(0x202e.toChar()))
    }

    @Test
    fun `the MCP tools serve the diff and the JSON format and refuse a bad format or a bad path`() {
        val tools = XrayMcpTools("x") { dir }
        val old = jar("old.jar", listOf(BenignFixture::class.java))
        val new = jar("new.jar", listOf(BenignFixture::class.java, ExecFixture::class.java))

        fun call(
            name: String,
            vararg args: Pair<String, Any?>,
        ) = runBlocking { tools.tools().first { it.name == name }.handler.call(McpToolArgs(args.toMap(), "{}")) }

        val text = call("xray_diff_jars", "old_path" to old.path, "new_path" to new.path)
        assertFalse(text.isError)
        assertTrue(text.text.contains("Capabilities GAINED"), text.text)

        val json = call("xray_diff_jars", "old_path" to old.path, "new_path" to new.path, "format" to "json")
        assertEquals("HIGH", MiniJson.parse(json.text).asObject()!!["addedRisk"])

        assertTrue(call("xray_scan_jar", "path" to old.path, "format" to "xml").isError)
        assertTrue(call("xray_diff_jars", "old_path" to old.path).isError)
        assertTrue(call("xray_diff_jars", "old_path" to old.path, "new_path" to File(dir, "absent.jar").path).isError)
        assertEquals("HIGH", MiniJson.parse(call("xray_scan_jar", "path" to new.path, "format" to "json").text).asObject()!!["topRisk"])
    }
}
