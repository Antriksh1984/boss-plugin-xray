package ai.rever.boss.plugin.dynamic.xray

/**
 * What changed between two builds of a plugin, in the terms that matter to someone deciding whether to load
 * the newer one: which capabilities it gained or lost, what new hosts its code names, and whether it now asks
 * for (or stopped asking for) permissions.
 *
 * Capabilities are compared by id, not by evidence, so a refactor that moves a call to another class is not a
 * change. Signature findings are left out: they describe the two files on disk, not the plugins.
 */
internal class ScanDiff(
    val old: ScanResult,
    val new: ScanResult,
    val addedCapabilities: List<CapabilityUse>,
    val removedCapabilities: List<CapabilityUse>,
    val addedHosts: List<String>,
    val removedHosts: List<String>,
    val addedFindings: List<Finding>,
    val removedFindings: List<Finding>,
    val addedPermissions: List<String>,
    val removedPermissions: List<String>,
) {
    val samePlugin: Boolean get() = old.pluginId != null && old.pluginId == new.pluginId

    /** The highest risk among what was ADDED: what the newer build can do that the older could not. */
    val addedRisk: Risk
        get() = (addedCapabilities.map { it.capability.risk } + addedFindings.map { it.risk }).maxOrNull() ?: Risk.INFO

    val verdict: String
        get() =
            when {
                old.unreadableReason != null || new.unreadableReason != null -> "NOT COMPARED - one of the JARs could not be scanned"
                addedRisk == Risk.HIGH -> "REVIEW BEFORE LOADING - the newer build gained high-risk capabilities"
                addedCapabilities.isNotEmpty() || addedFindings.any { it.risk >= Risk.MEDIUM } || addedHosts.isNotEmpty() ->
                    "REVIEW - the newer build gained capabilities"
                else -> "NO NEW CAPABILITIES in the newer build (static scan; see the limits of each report)"
            }

    companion object {
        fun of(
            old: ScanResult,
            new: ScanResult,
        ): ScanDiff {
            val oldCaps = old.capabilities.associateBy { it.capability.id }
            val newCaps = new.capabilities.associateBy { it.capability.id }
            val oldFindings = comparable(old).associateBy { it.id }
            val newFindings = comparable(new).associateBy { it.id }
            val oldPerms = old.manifest?.requiredPermissions.orEmpty().toSet()
            val newPerms = new.manifest?.requiredPermissions.orEmpty().toSet()
            return ScanDiff(
                old = old,
                new = new,
                addedCapabilities = newCaps.filterKeys { it !in oldCaps }.values.sortedByRisk(),
                removedCapabilities = oldCaps.filterKeys { it !in newCaps }.values.sortedByRisk(),
                addedHosts = (new.hosts - old.hosts.toSet()).sorted(),
                removedHosts = (old.hosts - new.hosts.toSet()).sorted(),
                addedFindings = newFindings.filterKeys { it !in oldFindings }.values.sortedByDescending { it.risk },
                removedFindings = oldFindings.filterKeys { it !in newFindings }.values.sortedByDescending { it.risk },
                addedPermissions = (newPerms - oldPerms).sorted(),
                removedPermissions = (oldPerms - newPerms).sorted(),
            )
        }

        private fun comparable(r: ScanResult) = r.findings.filterNot { it.id.startsWith("sig.") }

        private fun Collection<CapabilityUse>.sortedByRisk() =
            sortedWith(compareByDescending<CapabilityUse> { it.capability.risk }.thenBy { it.capability.id })
    }
}

internal object DiffReport {
    fun text(d: ScanDiff): String =
        buildString {
            appendLine("X-RAY DIFF")
            appendLine("  old      ${describe(d.old)}")
            appendLine("  new      ${describe(d.new)}")
            if (!d.samePlugin) {
                appendLine("  note     these JARs do not declare the same pluginId, so this compares two different plugins")
            }
            appendLine("  verdict  ${d.verdict}")

            section("Capabilities GAINED", d.addedCapabilities.map { "[${it.capability.risk}] ${it.capability.id} - ${it.capability.title}" })
            section("Capabilities dropped", d.removedCapabilities.map { "[${it.capability.risk}] ${it.capability.id} - ${it.capability.title}" })
            section("Findings introduced", d.addedFindings.map { "[${it.risk}] ${it.id} - ${it.title}" })
            section("Findings resolved", d.removedFindings.map { "[${it.risk}] ${it.id} - ${it.title}" })
            section("Hosts newly named in the code", d.addedHosts.map { SafeText.of(it, 80) })
            section("Hosts no longer named", d.removedHosts.map { SafeText.of(it, 80) })
            section("requiredPermissions added", d.addedPermissions.map { SafeText.of(it, 80) })
            section("requiredPermissions removed", d.removedPermissions.map { SafeText.of(it, 80) })

            appendLine()
            appendLine("Compared by capability id, so moving a call between classes is not a change.")
            appendLine("Both scans are static: neither sees code loaded or built at run time.")
        }

    private fun StringBuilder.section(
        title: String,
        lines: List<String>,
    ) {
        if (lines.isEmpty()) return
        appendLine()
        appendLine("$title (${lines.size})")
        lines.forEach { appendLine("  $it") }
    }

    private fun describe(r: ScanResult): String {
        val id = SafeText.of(r.pluginId ?: r.fileName)
        val version = r.manifest?.version?.let { " v${SafeText.of(it, 40)}" }.orEmpty()
        return "$id$version  (${SafeText.of(r.fileName)}, sha256 ${r.sha256?.take(12) ?: "n/a"})"
    }
}
