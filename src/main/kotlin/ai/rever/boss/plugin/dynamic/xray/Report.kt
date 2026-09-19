package ai.rever.boss.plugin.dynamic.xray

import java.io.File

/** Turns scan results into the text an agent or a person reads. Every string that came from a JAR goes through [SafeText]. */
internal object Report {
    fun verdict(result: ScanResult): String =
        when {
            result.unreadableReason != null -> "NOT SCANNED - ${result.unreadableReason}"
            result.topRisk == Risk.HIGH -> "REVIEW BEFORE LOADING - high-risk capabilities found"
            result.topRisk == Risk.MEDIUM -> "REVIEW - notable capabilities found"
            else -> "NO RISKY CAPABILITIES FOUND in the constant pools. This is not a safety guarantee: see the limits below."
        }

    fun scan(result: ScanResult): String =
        buildString {
            appendLine("X-RAY  ${SafeText.of(result.fileName)}")
            result.manifest?.let { m ->
                appendLine("  plugin   ${SafeText.of(m.pluginId ?: "(no pluginId)")}  v${SafeText.of(m.version ?: "?")}  (type ${SafeText.of(m.type ?: "?")}, api ${SafeText.of(m.apiVersion ?: "?")})")
            }
            appendLine("  sha256   ${result.sha256 ?: "(unavailable)"}")
            appendLine("  size     ${result.sizeBytes} bytes, ${result.classesScanned} class(es) read")
            appendLine("  verdict  ${verdict(result)}")

            if (result.capabilities.isNotEmpty()) {
                appendLine()
                appendLine("Capabilities (highest risk first)")
                for (use in result.capabilities) {
                    val c = use.capability
                    appendLine("  [${c.risk}] ${c.id} - ${c.title}")
                    appendLine("      why: ${c.why}")
                    val shown = use.evidence.joinToString("; ") { "${SafeText.of(it.className, 80)} (${SafeText.of(it.detail, 80)})" }
                    val more = use.classCount - use.evidence.map { it.className }.toSet().size
                    appendLine("      seen: $shown" + if (more > 0) " and $more more class(es)" else "")
                }
            }
            if (result.findings.isNotEmpty()) {
                appendLine()
                appendLine("Findings")
                for (f in result.findings.sortedByDescending { it.risk }) {
                    appendLine("  [${f.risk}] ${f.id} - ${f.title}")
                    appendLine("      ${f.detail}")
                }
            }
            if (result.hosts.isNotEmpty()) {
                appendLine()
                appendLine("Hosts named in string constants: ${result.hosts.joinToString(", ") { SafeText.of(it, 80) }}")
            }
            appendLine()
            appendLine("Limits")
            for (limit in result.limits) appendLine("  - $limit")
        }

    fun capabilities(): String =
        buildString {
            appendLine("Capabilities X-Ray recognises (${CapabilityCatalog.all.size}), highest risk first")
            for (c in CapabilityCatalog.all) {
                appendLine("  [${c.risk}] ${c.id} - ${c.title}")
                appendLine("      ${c.why}")
            }
            appendLine()
            appendLine("A capability is reported when a class REFERENCES the API, not when it is proven to run.")
        }
}

/** The result of scanning a directory of installed plugins. */
internal class InstalledReport(
    val directory: File,
    val results: List<ScanResult>,
    val duplicates: Map<String, List<String>>,
    val orphanSignatures: List<String>,
    val truncated: Boolean,
) {
    fun text(): String =
        buildString {
            appendLine("X-RAY  installed plugins in ${SafeText.of(directory.path)}")
            appendLine("  ${results.size} JAR(s) scanned" + if (truncated) " (list truncated at $MAX_JARS)" else "")
            appendLine()
            for (r in results.sortedWith(compareByDescending<ScanResult> { it.topRisk }.thenBy { it.fileName })) {
                val id = SafeText.of(r.pluginId ?: r.fileName)
                val high = r.capabilities.count { it.capability.risk == Risk.HIGH }
                val medium = r.capabilities.count { it.capability.risk == Risk.MEDIUM }
                val state = if (r.unreadableReason != null) "NOT SCANNED" else r.topRisk.name
                appendLine("  [$state] $id  ${SafeText.of(r.fileName)}  ($high high, $medium medium capabilities)")
            }
            if (duplicates.isNotEmpty()) {
                appendLine()
                appendLine("More than one JAR for the same plugin id (keep one per plugin):")
                for ((id, files) in duplicates) appendLine("  ${SafeText.of(id)}: ${files.joinToString(", ") { SafeText.of(it) }}")
            }
            if (orphanSignatures.isNotEmpty()) {
                appendLine()
                appendLine("Signature files with no matching JAR (safe to move away):")
                for (name in orphanSignatures) appendLine("  ${SafeText.of(name)}")
            }
            appendLine()
            appendLine("Run xray_scan_jar with a JAR's path for the full report.")
        }

    companion object {
        const val MAX_JARS = 200
    }
}

internal object InstalledScanner {
    fun scan(directory: File): InstalledReport? {
        if (!directory.isDirectory) return null
        val all = directory.listFiles().orEmpty()
        val jars = all.filter { it.isFile && it.name.endsWith(".jar", ignoreCase = true) }.sortedBy { it.name }
        val truncated = jars.size > InstalledReport.MAX_JARS
        val results = jars.take(InstalledReport.MAX_JARS).map { JarScanner.scan(it) }
        val duplicates =
            results
                .filter { it.pluginId != null }
                .groupBy { it.pluginId!! }
                .filterValues { it.size > 1 }
                .mapValues { (_, list) -> list.map { it.fileName } }
        val jarNames = jars.map { it.name }.toSet()
        val orphans = all.filter { it.isFile && it.name.endsWith(".jar.sig") && it.name.removeSuffix(".sig") !in jarNames }.map { it.name }.sorted()
        return InstalledReport(directory, results, duplicates, orphans, truncated)
    }
}
