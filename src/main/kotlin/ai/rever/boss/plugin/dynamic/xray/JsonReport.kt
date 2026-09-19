package ai.rever.boss.plugin.dynamic.xray

/**
 * The scan as JSON, for a CI step or an agent that wants fields instead of prose (for example "fail the build if
 * `topRisk` is HIGH" or "if a capability id appears that was not in the last release").
 *
 * Strings are escaped for JSON and, beyond what JSON requires, every control, line-separator, bidi and
 * zero-width character is written as a `\uXXXX` escape: the values came from inside a JAR.
 */
internal object JsonReport {
    private const val HEX_RADIX = 16
    private const val HEX_WIDTH = 4

    fun scan(r: ScanResult): String =
        obj(
            "file" to str(r.fileName),
            "sha256" to (r.sha256?.let { str(it) } ?: "null"),
            "sizeBytes" to r.sizeBytes.toString(),
            "verdict" to str(Report.verdict(r)),
            "topRisk" to str(r.topRisk.name),
            "unreadableReason" to (r.unreadableReason?.let { str(it) } ?: "null"),
            "plugin" to (r.manifest?.let { manifest(it) } ?: "null"),
            "classesScanned" to r.classesScanned.toString(),
            "classesUnreadable" to r.classesUnreadable.toString(),
            "capabilities" to arr(r.capabilities.map { capability(it) }),
            "findings" to arr(r.findings.map { finding(it) }),
            "hosts" to arr(r.hosts.map { str(it) }),
            "limits" to arr(r.limits.map { str(it) }),
        )

    fun diff(d: ScanDiff): String =
        obj(
            "verdict" to str(d.verdict),
            "samePlugin" to d.samePlugin.toString(),
            "addedRisk" to str(d.addedRisk.name),
            "old" to scan(d.old),
            "new" to scan(d.new),
            "addedCapabilities" to arr(d.addedCapabilities.map { capability(it) }),
            "removedCapabilities" to arr(d.removedCapabilities.map { capability(it) }),
            "addedFindings" to arr(d.addedFindings.map { finding(it) }),
            "removedFindings" to arr(d.removedFindings.map { finding(it) }),
            "addedHosts" to arr(d.addedHosts.map { str(it) }),
            "removedHosts" to arr(d.removedHosts.map { str(it) }),
            "addedPermissions" to arr(d.addedPermissions.map { str(it) }),
            "removedPermissions" to arr(d.removedPermissions.map { str(it) }),
        )

    private fun manifest(m: ManifestInfo) =
        obj(
            "pluginId" to (m.pluginId?.let { str(it) } ?: "null"),
            "version" to (m.version?.let { str(it) } ?: "null"),
            "apiVersion" to (m.apiVersion?.let { str(it) } ?: "null"),
            "mainClass" to (m.mainClass?.let { str(it) } ?: "null"),
            "type" to (m.type?.let { str(it) } ?: "null"),
            "requiredPermissions" to arr(m.requiredPermissions.map { str(it) }),
        )

    private fun capability(u: CapabilityUse) =
        obj(
            "id" to str(u.capability.id),
            "risk" to str(u.capability.risk.name),
            "title" to str(u.capability.title),
            "why" to str(u.capability.why),
            "classCount" to u.classCount.toString(),
            "evidence" to arr(u.evidence.map { obj("class" to str(it.className), "detail" to str(it.detail)) }),
        )

    private fun finding(f: Finding) =
        obj("id" to str(f.id), "risk" to str(f.risk.name), "title" to str(f.title), "detail" to str(f.detail))

    private fun obj(vararg fields: Pair<String, String>) = fields.joinToString(",", "{", "}") { (k, v) -> "${str(k)}:$v" }

    private fun arr(items: List<String>) = items.joinToString(",", "[", "]")

    private val forcedEscapes: Set<Char> =
        buildSet {
            add(0x061c.toChar())
            for (code in 0x200b..0x200f) add(code.toChar())
            for (code in 0x2028..0x202e) add(code.toChar())
            for (code in 0x2060..0x2064) add(code.toChar())
            for (code in 0x2066..0x2069) add(code.toChar())
            add(0xfeff.toChar())
        }

    private fun str(s: String): String {
        val out = StringBuilder("\"")
        for (c in s) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c.code < 0x20 || c.code in 0x7f..0x9f || c in forcedEscapes ->
                    out.append("\\u").append(c.code.toString(HEX_RADIX).padStart(HEX_WIDTH, '0'))
                else -> out.append(c)
            }
        }
        return out.append('"').toString()
    }
}
