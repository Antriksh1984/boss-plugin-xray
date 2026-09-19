package ai.rever.boss.plugin.dynamic.xray

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Each capability is recognised in a real compiled class, and the catalogue cannot drift from the API it describes. */
class CapabilityCatalogTest {
    private fun ids(cls: Class<*>) = Fixtures.ids(cls)

    @Test
    fun `running other programs is recognised`() {
        assertTrue("process.exec" in ids(ExecFixture::class.java))
    }

    @Test
    fun `outbound network use is recognised and the listening kind is separate`() {
        assertTrue("net.client" in ids(NetFixture::class.java))
        assertTrue("net.listen" in ids(ListenFixture::class.java))
        assertTrue("net.listen" !in ids(NetFixture::class.java))
    }

    @Test
    fun `file writes deletes and reads are three different capabilities`() {
        val found = ids(FileFixture::class.java)
        assertTrue("fs.write" in found, "$found")
        assertTrue("fs.delete" in found, "$found")
        assertTrue("fs.read" in found, "$found")
    }

    @Test
    fun `reflection and access bypass are recognised`() {
        val found = ids(ReflectFixture::class.java)
        assertTrue("reflect.use" in found, "$found")
        assertTrue("reflect.access" in found, "$found")
    }

    @Test
    fun `native code environment and exit are recognised`() {
        assertTrue("native.code" in ids(NativeFixture::class.java))
        assertTrue("env.read" in ids(EnvFixture::class.java))
        assertTrue("jvm.exit" in ids(ExitFixture::class.java))
    }

    @Test
    fun `a credential path in a string constant is recognised`() {
        assertTrue("cred.path" in ids(CredentialPathFixture::class.java))
    }

    @Test
    fun `subclassing a class loader is recognised from the superclass alone`() {
        assertTrue("dynamic.classload" in ids(LoaderFixture::class.java))
    }

    @Test
    fun `references after long and double constants are still found`() {
        // A long or double takes two pool slots. Miscounting them shifts every later entry and the
        // Runtime.exec reference below would be read as something else.
        assertTrue("process.exec" in ids(WideConstantsFixture::class.java))
    }

    @Test
    fun `host APIs are recognised by getter, by type and by the ungated project rewrite`() {
        val found = ids(HostApiFixture::class.java)
        assertTrue("host.secrets" in found, "$found")
        assertTrue("host.event-bus" in found, "$found")
        assertTrue("host.project-search" in found, "$found")
        assertTrue("host.project-replace" in found, "$found")
        assertTrue("host.mcp" in found, "$found")
    }

    @Test
    fun `a class that touches nothing reports nothing`() {
        assertEquals(emptySet(), ids(BenignFixture::class.java))
    }

    @Test
    fun `evidence names the class and the reference`() {
        val hit = CapabilityCatalog.detect(Fixtures.info(ExecFixture::class.java)).first { it.capability.id == "process.exec" }
        assertEquals("ai/rever/boss/plugin/dynamic/xray/ExecFixture", hit.evidence.className)
        assertTrue(hit.evidence.detail.startsWith("java/lang/"), hit.evidence.detail)
    }

    @Test
    fun `capability ids are unique and every one carries a reason`() {
        val all = CapabilityCatalog.all
        assertEquals(all.size, all.map { it.id }.toSet().size)
        assertTrue(all.all { it.why.isNotBlank() && it.title.isNotBlank() })
    }

    @Test
    fun `every host type the catalogue names exists in the plugin API`() {
        val missing =
            CapabilityCatalog.hostTypes.values
                .flatten()
                .filter { runCatching { Class.forName(it.replace('/', '.')) }.isFailure }
        assertEquals(emptyList(), missing, "the API renamed or removed a type the catalogue relies on")
    }

    @Test
    fun `every PluginContext getter the catalogue names exists`() {
        val declared =
            Class
                .forName("ai.rever.boss.plugin.api.PluginContext")
                .methods
                .map { it.name }
                .toSet()
        val missing = CapabilityCatalog.contextGetters.values.flatten().filter { it !in declared }
        assertEquals(emptyList(), missing, "the API renamed or removed a getter the catalogue relies on")
    }

    @Test
    fun `the scanner passes its own scan`() {
        // The plugin registers MCP tools and reads files. It must reference nothing more: it should not
        // spawn processes, open connections, or ask the host for a single provider it reports on.
        val classes = File(System.getProperty("xray.mainClasses")).walkTopDown().filter { it.extension == "class" }.toList()
        assertTrue(classes.isNotEmpty(), "no compiled plugin classes found")
        val seen = classes.flatMap { CapabilityCatalog.detect(ClassFileReader.read(it.readBytes())) }.map { it.capability.id }.toSet()
        // cred.path: the catalogue itself contains the credential-file names it looks for (".ssh/", ".npmrc").
        val allowed = setOf("host.mcp", "fs.read", "reflect.use", "cred.path")
        assertTrue(seen.all { it in allowed }, "the scanner itself references: ${seen - allowed}")
    }
}
