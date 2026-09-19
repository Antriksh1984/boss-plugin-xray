package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.McpToolDefinition
import ai.rever.boss.plugin.api.McpToolHandler
import ai.rever.boss.plugin.api.McpToolProvider
import ai.rever.boss.plugin.api.McpToolResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * The three MCP tools. All are read-only: nothing is loaded, run, written, moved or deleted.
 *
 * Scanning reads and inflates archive bytes, so each call runs on the IO dispatcher, and a scan that
 * does not finish inside the host's own 60-second limit is cancelled by it rather than by anything here.
 */
internal class XrayMcpTools(
    override val providerId: String,
    private val pluginsDirectory: () -> File = { File(System.getProperty("user.home"), ".boss/plugins") },
) : McpToolProvider {
    override fun tools(): List<McpToolDefinition> =
        listOf(
            McpToolDefinition(
                name = "xray_scan_jar",
                description =
                    "Statically scan a plugin JAR and report what it can do (processes, network, files, host APIs) " +
                        "before it is loaded. Read-only. Static: it reports what classes reference, not proof of behaviour.",
                inputSchema =
                    """{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to a local .jar file"}},"required":["path"]}""",
                readOnly = true,
                handler = McpToolHandler { args -> scanJar(args.string("path")) },
            ),
            McpToolDefinition(
                name = "xray_scan_installed",
                description =
                    "Scan every JAR in ~/.boss/plugins: risk summary per plugin, plus duplicate JARs for one plugin id " +
                        "and leftover .jar.sig files. Read-only.",
                inputSchema = """{"type":"object","properties":{}}""",
                readOnly = true,
                handler = McpToolHandler { scanInstalled() },
            ),
            McpToolDefinition(
                name = "xray_capabilities",
                description = "List every capability X-Ray recognises, its risk level and why it matters.",
                inputSchema = """{"type":"object","properties":{}}""",
                readOnly = true,
                handler = McpToolHandler { McpToolResult(Report.capabilities(), isError = false) },
            ),
        )

    private suspend fun scanJar(path: String?): McpToolResult =
        when (val verdict = ToolPaths.check(path)) {
            is ToolPaths.Verdict.Refused -> McpToolResult(verdict.reason, isError = true)
            is ToolPaths.Verdict.Ok ->
                withContext(Dispatchers.IO) { McpToolResult(Report.scan(JarScanner.scan(verdict.file)), isError = false) }
        }

    private suspend fun scanInstalled(): McpToolResult =
        withContext(Dispatchers.IO) {
            val report = InstalledScanner.scan(pluginsDirectory())
            if (report == null) {
                McpToolResult("No plugins directory found.", isError = true)
            } else {
                McpToolResult(report.text(), isError = false)
            }
        }
}
