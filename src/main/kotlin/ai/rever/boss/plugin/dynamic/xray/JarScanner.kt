package ai.rever.boss.plugin.dynamic.xray

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipException
import java.util.zip.ZipFile

/** A problem or observation about the JAR as a whole, as opposed to one capability. */
internal data class Finding(
    val id: String,
    val risk: Risk,
    val title: String,
    val detail: String,
)

/** A capability, everywhere it was seen. */
internal data class CapabilityUse(
    val capability: Capability,
    val evidence: List<Evidence>,
    val classCount: Int,
)

/** The parts of `plugin.json` the scan reasons about. Every value is text from the JAR and must be escaped when shown. */
internal data class ManifestInfo(
    val pluginId: String?,
    val displayName: String?,
    val version: String?,
    val apiVersion: String?,
    val mainClass: String?,
    val type: String?,
    val requiredPermissions: List<String>,
)

internal class ScanResult(
    val fileName: String,
    val sizeBytes: Long,
    val sha256: String?,
    val manifest: ManifestInfo?,
    val classesScanned: Int,
    val classesUnreadable: Int,
    val capabilities: List<CapabilityUse>,
    val findings: List<Finding>,
    val hosts: List<String>,
    /** Why the picture may be incomplete. Always shown: a scan that hid its limits would read as a clean bill. */
    val limits: List<String>,
    /** Set when the file could not be scanned at all. */
    val unreadableReason: String? = null,
) {
    val topRisk: Risk
        get() =
            (capabilities.map { it.capability.risk } + findings.map { it.risk })
                .maxOrNull() ?: Risk.INFO

    val pluginId: String? get() = manifest?.pluginId
}

/**
 * Reads a plugin JAR and reports what its classes reach for.
 *
 * Static and read-only: no class is loaded or run, nothing is written, and the file is only opened for
 * reading. Bounded in every direction, because the JAR is a stranger's: a cap on the file, on the number
 * of entries, on the bytes read for one class and on the bytes read overall, none of which trusts the
 * sizes the archive declares for itself.
 */
internal object JarScanner {
    const val MAX_JAR_BYTES = 256L * 1024 * 1024
    const val MAX_ENTRIES = 20_000
    const val MAX_CLASS_BYTES = 8 * 1024 * 1024
    const val MAX_TOTAL_BYTES = 256L * 1024 * 1024
    private const val MAX_MANIFEST_BYTES = 1024 * 1024
    private const val MAX_HOSTS = 25
    private const val MAX_EVIDENCE = 5
    private const val SIGNATURE_STALE_MS = 2_000L
    private const val MANIFEST_PATH = "META-INF/boss-plugin/plugin.json"
    private val nativeSuffixes = listOf(".dll", ".so", ".dylib", ".jnilib")
    private val benignHosts = setOf("www.w3.org", "www.apache.org", "xmlpull.org", "java.sun.com", "xml.org", "www.jcp.org")
    private val urlHost = Regex("https?://([A-Za-z0-9][A-Za-z0-9.-]{0,252})")
    private val storeId = Regex("^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)+$")

    /** Permissions-gated host surfaces: using one with no `requiredPermissions` leaves it open to every signed-in user. */
    private val gateable =
        setOf("host.secrets", "host.brokered-credential", "host.store-key", "host.supabase", "host.admin")

    private class Tally {
        val perCapability = LinkedHashMap<String, MutableList<Evidence>>()
        val classesPerCapability = LinkedHashMap<String, MutableSet<String>>()
        val capabilities = LinkedHashMap<String, Capability>()
        val hosts = LinkedHashSet<String>()
        var scanned = 0
        var unreadable = 0
        var totalBytes = 0L
        var bundlesApi = 0
        var traversal = 0
        val nativeLibs = mutableListOf<String>()
        val nestedJars = mutableListOf<String>()
        val services = mutableListOf<String>()
        val classNames = HashSet<String>()
        val limits = mutableListOf<String>()
        var manifestText: String? = null
        var manifestProblem: String? = null
    }

    fun scan(file: File): ScanResult {
        val length = file.length()
        if (length > MAX_JAR_BYTES) {
            return unreadable(file, length, "larger than the $MAX_JAR_BYTES-byte limit, not opened")
        }
        val tally = Tally()
        try {
            ZipFile(file).use { zip -> readEntries(zip, tally) }
        } catch (_: ZipException) {
            return unreadable(file, length, "not a readable ZIP/JAR archive")
        } catch (e: IOException) {
            return unreadable(file, length, "could not be read (${e.javaClass.simpleName})")
        }

        val manifest = tally.manifestText?.let { parseManifest(it, tally) }
        val capabilities =
            tally.capabilities.values
                .map { cap ->
                    CapabilityUse(
                        cap,
                        tally.perCapability.getValue(cap.id).take(MAX_EVIDENCE),
                        tally.classesPerCapability.getValue(cap.id).size,
                    )
                }.sortedWith(compareByDescending<CapabilityUse> { it.capability.risk }.thenBy { it.capability.id })

        return ScanResult(
            fileName = file.name,
            sizeBytes = length,
            sha256 = sha256(file),
            manifest = manifest,
            classesScanned = tally.scanned,
            classesUnreadable = tally.unreadable,
            capabilities = capabilities,
            findings = findings(file, tally, manifest, capabilities),
            hosts = tally.hosts.toList(),
            limits = limits(tally),
        )
    }

    private fun unreadable(
        file: File,
        length: Long,
        reason: String,
    ) = ScanResult(
        fileName = file.name,
        sizeBytes = length,
        sha256 = null,
        manifest = null,
        classesScanned = 0,
        classesUnreadable = 0,
        capabilities = emptyList(),
        findings = emptyList(),
        hosts = emptyList(),
        limits = listOf("The file was not scanned."),
        unreadableReason = reason,
    )

    private fun readEntries(
        zip: ZipFile,
        tally: Tally,
    ) {
        var entries = 0
        val enumeration = zip.entries()
        while (enumeration.hasMoreElements()) {
            val entry = enumeration.nextElement()
            if (++entries > MAX_ENTRIES) {
                tally.limits += "Stopped after $MAX_ENTRIES entries; the rest of the archive was not read."
                return
            }
            if (entry.isDirectory) continue
            val name = entry.name
            if (isTraversal(name)) tally.traversal++
            when {
                name == MANIFEST_PATH -> readManifest(zip, entry, tally)
                name.endsWith(".class") -> if (!readClass(zip, entry, name, tally)) return
                nativeSuffixes.any { name.endsWith(it, ignoreCase = true) } -> tally.nativeLibs += name
                name.endsWith(".jar", ignoreCase = true) -> tally.nestedJars += name
                name.startsWith("META-INF/services/") && name.length > "META-INF/services/".length -> tally.services += name
            }
        }
    }

    private fun readManifest(
        zip: ZipFile,
        entry: java.util.zip.ZipEntry,
        tally: Tally,
    ) {
        val bytes = boundedEntry(zip, entry, MAX_MANIFEST_BYTES)
        if (bytes == null) {
            tally.manifestProblem = "plugin.json is larger than $MAX_MANIFEST_BYTES bytes"
        } else {
            tally.manifestText = String(bytes, Charsets.UTF_8)
        }
    }

    /** Returns false when the overall byte budget is spent and reading must stop. */
    private fun readClass(
        zip: ZipFile,
        entry: java.util.zip.ZipEntry,
        name: String,
        tally: Tally,
    ): Boolean {
        if (name.startsWith("ai/rever/boss/plugin/api/")) tally.bundlesApi++
        val bytes = boundedEntry(zip, entry, MAX_CLASS_BYTES)
        if (bytes == null) {
            tally.unreadable++
            tally.limits += "A class over $MAX_CLASS_BYTES bytes, or with corrupt compressed data, was skipped."
            return true
        }
        tally.totalBytes += bytes.size
        if (tally.totalBytes > MAX_TOTAL_BYTES) {
            tally.limits += "Stopped after reading $MAX_TOTAL_BYTES bytes of classes."
            return false
        }
        val info =
            try {
                ClassFileReader.read(bytes)
            } catch (_: MalformedClassException) {
                tally.unreadable++
                return true
            }
        tally.scanned++
        tally.classNames += info.name
        for (hit in CapabilityCatalog.detect(info)) record(tally, hit)
        for (s in info.strings) {
            if (tally.hosts.size >= MAX_HOSTS) break
            val host = urlHost.find(s)?.groupValues?.get(1)?.lowercase()
            if (host != null && host !in benignHosts) tally.hosts += host
        }
        return true
    }

    private fun record(
        tally: Tally,
        hit: Hit,
    ) {
        val id = hit.capability.id
        tally.capabilities.putIfAbsent(id, hit.capability)
        tally.perCapability.getOrPut(id) { mutableListOf() }.add(hit.evidence)
        tally.classesPerCapability.getOrPut(id) { LinkedHashSet() }.add(hit.evidence.className)
    }

    private fun parseManifest(
        text: String,
        tally: Tally,
    ): ManifestInfo? =
        try {
            val obj = MiniJson.parse(text).asObject() ?: throw JsonException("plugin.json is not an object")
            ManifestInfo(
                pluginId = obj["pluginId"] as? String,
                displayName = obj["displayName"] as? String,
                version = obj["version"] as? String,
                apiVersion = obj["apiVersion"] as? String,
                mainClass = obj["mainClass"] as? String,
                type = obj["type"] as? String,
                requiredPermissions = obj["requiredPermissions"].asStringList(),
            )
        } catch (e: JsonException) {
            tally.manifestProblem = "plugin.json could not be read: ${e.message}"
            null
        }

    private fun findings(
        file: File,
        tally: Tally,
        manifest: ManifestInfo?,
        capabilities: List<CapabilityUse>,
    ): List<Finding> {
        val out = mutableListOf<Finding>()
        fun add(
            id: String,
            risk: Risk,
            title: String,
            detail: String,
        ) {
            out += Finding(id, risk, title, detail)
        }

        manifestFindings(tally, manifest, ::add)
        val ids = capabilities.map { it.capability.id }.toSet()

        if (tally.nativeLibs.isNotEmpty()) {
            add("jar.native-library", Risk.HIGH, "Bundles native libraries", "${tally.nativeLibs.size} file(s), for example ${SafeText.of(tally.nativeLibs.first())}. Native code is not analysed here.")
        }
        if (tally.nestedJars.isNotEmpty()) {
            add("jar.nested-jar", Risk.MEDIUM, "Bundles other JARs", "${tally.nestedJars.size} nested JAR(s), for example ${SafeText.of(tally.nestedJars.first())}. Their contents were not scanned.")
        }
        if (tally.bundlesApi > 0) {
            add("jar.bundles-host-api", Risk.MEDIUM, "Bundles copies of the host's plugin API classes", "${tally.bundlesApi} class(es) under ai/rever/boss/plugin/api. The host loads its own copy first; a bundled one only risks version skew.")
        }
        if (tally.traversal > 0) {
            add("jar.path-traversal", Risk.MEDIUM, "Entry names that climb out of the archive", "${tally.traversal} entry name(s) contain .. or an absolute path. Anything that unpacks this JAR to disk would write outside its target.")
        }
        if (tally.services.isNotEmpty()) {
            add("jar.service-providers", Risk.LOW, "Declares ServiceLoader providers", "${tally.services.size} META-INF/services file(s).")
        }
        if ("net.client" in ids || "net.listen" in ids) {
            val secretish = ids.any { it in SECRET_SOURCES }
            val readsData = ids.any { it in DATA_SOURCES }
            if (secretish) {
                add("combo.secret-and-network", Risk.HIGH, "Can read credentials and reach the network", "It mentions both a way to obtain secrets and a way to send data off the machine. That is the shape of an exfiltration path, not proof of one.")
            } else if (readsData) {
                add("combo.data-and-network", Risk.MEDIUM, "Can read local data and reach the network", "It mentions both a way to read local data and a way to send data off the machine.")
            }
        }
        if (manifest != null) {
            val gated = ids.filter { it in gateable }
            if (gated.isNotEmpty() && manifest.requiredPermissions.isEmpty()) {
                add("manifest.ungated-sensitive-api", Risk.MEDIUM, "Uses a sensitive host API but declares no requiredPermissions", "${gated.joinToString()}. An empty requiredPermissions leaves the plugin open to every signed-in user.")
            }
        }
        signatureFinding(file, ::add)
        return out
    }

    private fun manifestFindings(
        tally: Tally,
        manifest: ManifestInfo?,
        add: (String, Risk, String, String) -> Unit,
    ) {
        if (manifest == null) {
            add(
                "manifest.unreadable",
                Risk.MEDIUM,
                if (tally.manifestText == null && tally.manifestProblem == null) "No plugin.json in the JAR" else "plugin.json could not be read",
                tally.manifestProblem ?: "The host cannot load a JAR without META-INF/boss-plugin/plugin.json.",
            )
            return
        }
        val main = manifest.mainClass
        if (main == null) {
            add("manifest.no-main-class", Risk.MEDIUM, "plugin.json names no mainClass", "The host has nothing to instantiate.")
        } else if (main.replace('.', '/') !in tally.classNames) {
            add("manifest.main-class-missing", Risk.MEDIUM, "mainClass is not in the JAR", "${SafeText.of(main)} was not found among the ${tally.scanned} readable classes.")
        }
        val id = manifest.pluginId
        if (id == null || !storeId.matches(id)) {
            add("manifest.plugin-id", Risk.LOW, "pluginId is missing or not in store form", "The store accepts lowercase reverse-domain ids only.")
        }
    }

    private fun signatureFinding(
        file: File,
        add: (String, Risk, String, String) -> Unit,
    ) {
        val sig = File(file.path + ".sig")
        if (!sig.isFile) {
            add("sig.none", Risk.INFO, "No .jar.sig next to the JAR", "Installations that enforce signatures reject an unsigned local JAR.")
        } else if (sig.lastModified() + SIGNATURE_STALE_MS < file.lastModified()) {
            add("sig.stale", Risk.MEDIUM, "The .jar.sig is older than the JAR", "It was probably made for different bytes, and the host will refuse to load this JAR against it. Move it away before replacing a plugin.")
        }
    }

    private fun limits(tally: Tally): List<String> {
        val out = mutableListOf<String>()
        out += "Static scan of ${tally.scanned} class constant pool(s); code loaded or built at run time is not visible."
        if (tally.unreadable > 0) out += "${tally.unreadable} class file(s) could not be read."
        if (tally.nestedJars.isNotEmpty()) out += "Nested JARs were not opened."
        out += tally.limits.distinct()
        return out
    }

    private val SECRET_SOURCES = setOf("host.secrets", "host.brokered-credential", "host.store-key", "host.supabase", "cred.path", "env.read")
    private val DATA_SOURCES =
        setOf("fs.read", "host.filesystem", "host.project-search", "host.editor", "host.clipboard", "clipboard.system", "host.browser", "host.event-bus", "host.active-tabs", "host.screen-capture")

    private fun isTraversal(name: String): Boolean =
        name.startsWith("/") || name.contains('\\') || name.split('/').any { it == ".." }

    /** One entry's bytes, or null when it is over [max] or its compressed data is corrupt: either way the entry is skipped. */
    private fun boundedEntry(
        zip: ZipFile,
        entry: java.util.zip.ZipEntry,
        max: Int,
    ): ByteArray? =
        try {
            zip.getInputStream(entry).use { readBounded(it, max) }
        } catch (_: IOException) {
            null
        }

    /** Reads at most [max] bytes and returns null when the stream holds more, without trusting any declared size. */
    private fun readBounded(
        input: InputStream,
        max: Int,
    ): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER)
        var total = 0
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            total += n
            if (total > max) return null
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    private const val BUFFER = 16 * 1024

    private fun sha256(file: File): String? =
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(BUFFER)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: IOException) {
            null
        }
}
