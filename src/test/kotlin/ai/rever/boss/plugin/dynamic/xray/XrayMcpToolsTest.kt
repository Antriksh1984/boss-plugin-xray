package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.McpToolArgs
import ai.rever.boss.plugin.api.McpToolResult
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class XrayMcpToolsTest {
    private val dir = createTempDirectory("xray-tools").toFile()
    private val tools = XrayMcpTools("ai.rever.boss.plugin.dynamic.xray") { dir }

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun call(
        name: String,
        vararg args: Pair<String, Any?>,
    ): McpToolResult {
        val tool = tools.tools().first { it.name == name }
        return runBlocking { tool.handler.call(McpToolArgs(args.toMap(), "{}")) }
    }

    private fun writeJar(
        name: String,
        id: String,
        vararg classes: Class<*>,
    ): File {
        val file = File(dir, name)
        JarOutputStream(file.outputStream()).use { out ->
            out.putNextEntry(JarEntry("META-INF/boss-plugin/plugin.json"))
            out.write("""{"pluginId":"$id","displayName":"D","version":"1.0.0","apiVersion":"1.0.20","mainClass":"a.B"}""".toByteArray())
            out.closeEntry()
            for (c in classes) {
                out.putNextEntry(JarEntry(c.name.replace('.', '/') + ".class"))
                out.write(Fixtures.bytes(c))
                out.closeEntry()
            }
        }
        return file
    }

    @Test
    fun `every tool is read-only and named in the plugin's own namespace`() {
        val all = tools.tools()
        assertEquals(setOf("xray_scan_jar", "xray_scan_installed", "xray_capabilities"), all.map { it.name }.toSet())
        assertTrue(all.all { it.readOnly }, "a scanner must never declare a side effect it does not have")
    }

    @Test
    fun `scanning a jar returns the report`() {
        val jar = writeJar("p.jar", "ai.rever.boss.plugin.dynamic.p", ExecFixture::class.java)
        val result = call("xray_scan_jar", "path" to jar.path)
        assertFalse(result.isError)
        assertTrue(result.text.contains("process.exec"), result.text)
        assertTrue(result.text.contains("REVIEW BEFORE LOADING"), result.text)
    }

    @Test
    fun `a bad path is an error result and not an exception`() {
        assertTrue(call("xray_scan_jar").isError)
        assertTrue(call("xray_scan_jar", "path" to "notes.txt").isError)
        assertTrue(call("xray_scan_jar", "path" to File(dir, "absent.jar").path).isError)
    }

    @Test
    fun `installed scan ranks plugins and finds duplicates and orphan signatures`() {
        writeJar("risky-1.jar", "ai.rever.boss.plugin.dynamic.risky", ExecFixture::class.java)
        writeJar("risky-2.jar", "ai.rever.boss.plugin.dynamic.risky", BenignFixture::class.java)
        writeJar("calm.jar", "ai.rever.boss.plugin.dynamic.calm", BenignFixture::class.java)
        File(dir, "gone.jar.sig").writeText("sig")

        val text = call("xray_scan_installed").text
        assertTrue(text.contains("3 JAR(s) scanned"), text)
        assertTrue(text.indexOf("[HIGH]") in 0 until text.indexOf("calm.jar"), "the riskiest plugin is listed first:\n$text")
        assertTrue(text.contains("More than one JAR for the same plugin id"), text)
        assertTrue(text.contains("ai.rever.boss.plugin.dynamic.risky: risky-1.jar, risky-2.jar"), text)
        assertTrue(text.contains("gone.jar.sig"), text)
    }

    @Test
    fun `a missing plugins directory is reported`() {
        val missing = XrayMcpTools("x") { File(dir, "nope") }
        val result = runBlocking { missing.tools().first { it.name == "xray_scan_installed" }.handler.call(McpToolArgs(emptyMap(), "{}")) }
        assertTrue(result.isError)
    }

    @Test
    fun `the capability list is served`() {
        val text = call("xray_capabilities").text
        assertTrue(text.contains("process.exec") && text.contains("host.project-replace"), text)
        assertTrue(text.contains("REFERENCES"), "the list says it reports references, not proof")
    }
}
