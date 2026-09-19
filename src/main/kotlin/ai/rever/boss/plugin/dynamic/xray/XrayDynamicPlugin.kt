package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.DynamicPlugin
import ai.rever.boss.plugin.api.PluginContext

/**
 * Plugin X-Ray: read-only static analysis of plugin JARs, exposed to agents as MCP tools.
 *
 * It registers tools and nothing else. It asks the host for no provider, so it uses none of the
 * capabilities it reports on, and it declares no `requiredPermissions` because there is nothing here
 * to gate: reading a JAR the caller already has access to gives the caller nothing new.
 */
class XrayDynamicPlugin : DynamicPlugin {
    override val pluginId = "ai.rever.boss.plugin.dynamic.xray"
    override val displayName = "Plugin X-Ray"
    override val version = "0.1.0"
    override val description = "Read-only static scan of a plugin JAR: what it can do, before you load it"
    override val author = "Antriksh"
    override val url = "https://github.com/Antriksh1984/boss-plugin-xray"

    override fun register(context: PluginContext) {
        context.registerMcpToolProvider(XrayMcpTools(pluginId))
    }
}
