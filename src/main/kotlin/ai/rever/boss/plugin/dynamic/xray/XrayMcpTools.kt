package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.McpToolDefinition
import ai.rever.boss.plugin.api.McpToolHandler
import ai.rever.boss.plugin.api.McpToolProvider
import ai.rever.boss.plugin.api.McpToolResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

private const val BAD_FORMAT = "format must be text or json"

/**
 * The four MCP tools. All are read-only: nothing is loaded, run, written, moved or deleted.
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
                    """{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to a local .jar file"},"format":{"type":"string","description":"text (default) or json"}},"required":["path"]}""",
                readOnly = true,
                handler = McpToolHandler { args -> scanJar(args.string("path"), args.string("format")) },
            ),
            McpToolDefinition(
                name = "xray_diff_jars",
                description =
                    "Compare two builds or versions of a plugin JAR and report what the newer one GAINED or dropped: " +
                        "capabilities, hosts named in the code, findings, requiredPermissions. Use it before loading an update " +
                        "or after a rebuild. Read-only, static.",
                inputSchema =
                    """{"type":"object","properties":{"old_path":{"type":"string","description":"Absolute path to the older .jar"},"new_path":{"type":"string","description":"Absolute path to the newer .jar"},"format":{"type":"string","description":"text (default) or json"}},"required":["old_path","new_path"]}""",
                readOnly = true,
                handler = McpToolHandler { args -> diffJars(args.string("old_path"), args.string("new_path"), args.string("format")) },
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

    private suspend fun scanJar(
        path: String?,
        format: String?,
    ): McpToolResult {
        val json = wantsJson(format) ?: return McpToolResult(BAD_FORMAT, isError = true)
        return when (val verdict = ToolPaths.check(path)) {
            is ToolPaths.Verdict.Refused -> McpToolResult(verdict.reason, isError = true)
            is ToolPaths.Verdict.Ok ->
                withContext(Dispatchers.IO) {
                    val result = JarScanner.scan(verdict.file)
                    McpToolResult(if (json) JsonReport.scan(result) else Report.scan(result), isError = false)
                }
        }
    }

    private suspend fun diffJars(
        oldPath: String?,
        newPath: String?,
        format: String?,
    ): McpToolResult {
        val json = wantsJson(format) ?: return McpToolResult(BAD_FORMAT, isError = true)
        val old = ToolPaths.check(oldPath)
        val new = ToolPaths.check(newPath)
        return when {
            old is ToolPaths.Verdict.Refused -> McpToolResult("old_path: ${old.reason}", isError = true)
            new is ToolPaths.Verdict.Refused -> McpToolResult("new_path: ${new.reason}", isError = true)
            old is ToolPaths.Verdict.Ok && new is ToolPaths.Verdict.Ok ->
                withContext(Dispatchers.IO) {
                    val diff = ScanDiff.of(JarScanner.scan(old.file), JarScanner.scan(new.file))
                    McpToolResult(if (json) JsonReport.diff(diff) else DiffReport.text(diff), isError = false)
                }
            else -> McpToolResult("unreachable", isError = true)
        }
    }

    /** true for json, false for text, null for anything else. */
    private fun wantsJson(format: String?): Boolean? =
        when (format?.trim()?.lowercase()) {
            null, "", "text" -> false
            "json" -> true
            else -> null
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
