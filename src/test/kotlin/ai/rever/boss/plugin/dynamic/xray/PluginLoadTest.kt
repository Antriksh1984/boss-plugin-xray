package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.McpToolArgs
import ai.rever.boss.plugin.api.McpToolProvider
import kotlinx.coroutines.runBlocking
import java.io.File
import java.lang.reflect.Proxy
import java.net.URLClassLoader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Loads the BUILT plugin JAR the way the host does, and not from the test classpath.
 *
 * The plugin class loader here can see only the plugin API, Kotlin and coroutines, which is what a real
 * plugin gets from the host. The JAR's own classes are not on the test classpath's parent chain, so if the
 * JAR were missing a class, or plugin.json named a class that is not in it, this fails where the unit tests
 * (which run against compiled directories) cannot.
 */
class PluginLoadTest {
    private val pluginJar = File(System.getProperty("xray.pluginJar"))

    /**
     * What the host shows a plugin: the JDK, Kotlin, coroutines and the plugin API, shared with this test so
     * types have one identity, and nothing else. In particular not this project's own classes, which are on
     * the test classpath but must come from the JAR under test.
     */
    private class HostLikeLoader(
        parent: ClassLoader,
    ) : ClassLoader(parent) {
        private val visible =
            listOf("java.", "javax.", "jdk.", "sun.", "com.sun.", "kotlin.", "kotlinx.", "org.jetbrains.", "ai.rever.boss.plugin.api.", "ai.rever.boss.plugin.browser.")

        override fun loadClass(
            name: String,
            resolve: Boolean,
        ): Class<*> {
            if (visible.none { name.startsWith(it) }) throw ClassNotFoundException(name)
            return super.loadClass(name, resolve)
        }
    }

    private fun hostLikeLoader(): ClassLoader = HostLikeLoader(javaClass.classLoader)

    private fun manifest(): Map<String, Any?> {
        java.util.zip.ZipFile(pluginJar).use { zip ->
            val entry = assertNotNull(zip.getEntry("META-INF/boss-plugin/plugin.json"), "plugin.json is not in the JAR")
            return MiniJson.parse(zip.getInputStream(entry).readBytes().toString(Charsets.UTF_8)).asObject()!!
        }
    }

    @Test
    fun `the built JAR carries a manifest that agrees with the code`() {
        val m = manifest()
        assertEquals("ai.rever.boss.plugin.dynamic.xray", m["pluginId"])
        assertEquals("ai.rever.boss.plugin.dynamic.xray.XrayDynamicPlugin", m["mainClass"])
        val host = hostLikeLoader()
        URLClassLoader(arrayOf(pluginJar.toURI().toURL()), host).use { loader ->
            val plugin = loader.loadClass(m["mainClass"] as String).getDeclaredConstructor().newInstance()
            val dynamic = plugin as ai.rever.boss.plugin.api.DynamicPlugin
            assertEquals(m["pluginId"], dynamic.pluginId)
            assertEquals(m["version"], dynamic.version, "plugin.json and the code must name one version")
        }
    }

    @Test
    fun `registering exposes exactly the four read-only tools and no other host surface`() {
        val host = hostLikeLoader()
        URLClassLoader(arrayOf(pluginJar.toURI().toURL()), host).use { loader ->
            val plugin = loader.loadClass("ai.rever.boss.plugin.dynamic.xray.XrayDynamicPlugin").getDeclaredConstructor().newInstance()
            val contextType = host.loadClass("ai.rever.boss.plugin.api.PluginContext")
            val calls = mutableListOf<String>()
            var provider: McpToolProvider? = null
            val context =
                Proxy.newProxyInstance(host, arrayOf(contextType)) { _, method, args ->
                    calls += method.name
                    if (method.name == "registerMcpToolProvider") provider = args[0] as McpToolProvider
                    null
                }
            plugin.javaClass.getMethod("register", contextType).invoke(plugin, context)

            assertEquals(listOf("registerMcpToolProvider"), calls, "the plugin must ask the host for nothing else")
            val tools = assertNotNull(provider).tools()
            assertEquals(setOf("xray_scan_jar", "xray_diff_jars", "xray_scan_installed", "xray_capabilities"), tools.map { it.name }.toSet())
            assertTrue(tools.all { it.readOnly })
        }
    }

    @Test
    fun `the loaded plugin can scan its own JAR`() {
        val host = hostLikeLoader()
        URLClassLoader(arrayOf(pluginJar.toURI().toURL()), host).use { loader ->
            val plugin = loader.loadClass("ai.rever.boss.plugin.dynamic.xray.XrayDynamicPlugin").getDeclaredConstructor().newInstance()
            val contextType = host.loadClass("ai.rever.boss.plugin.api.PluginContext")
            var provider: McpToolProvider? = null
            val context =
                Proxy.newProxyInstance(host, arrayOf(contextType)) { _, method, args ->
                    if (method.name == "registerMcpToolProvider") provider = args[0] as McpToolProvider
                    null
                }
            plugin.javaClass.getMethod("register", contextType).invoke(plugin, context)

            val scan = assertNotNull(provider).tools().first { it.name == "xray_scan_jar" }
            val result = runBlocking { scan.handler.call(McpToolArgs(mapOf("path" to pluginJar.path), "{}")) }
            assertTrue(!result.isError, result.text)
            assertTrue(result.text.contains("ai.rever.boss.plugin.dynamic.xray"), result.text)
            assertTrue(!result.text.contains("process.exec") && !result.text.contains("net.client"), result.text)
        }
    }
}
