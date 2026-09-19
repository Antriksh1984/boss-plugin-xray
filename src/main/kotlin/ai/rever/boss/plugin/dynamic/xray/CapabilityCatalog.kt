package ai.rever.boss.plugin.dynamic.xray

internal enum class Risk { INFO, LOW, MEDIUM, HIGH }

/**
 * Something a plugin can do, named in terms a reviewer can act on.
 *
 * [why] is the reason the capability matters, and for the host APIs it is taken from what the host
 * itself documents about that surface (an event bus every plugin can read, a project rewrite that no
 * permission gates, a vault). The ranking is a judgement, so the text says why rather than only how bad.
 */
internal data class Capability(
    val id: String,
    val risk: Risk,
    val title: String,
    val why: String,
)

/** One place a capability was seen: the class and the reference that triggered it. */
internal data class Evidence(
    val className: String,
    val detail: String,
)

internal data class Hit(
    val capability: Capability,
    val evidence: Evidence,
)

private const val API = "ai/rever/boss/plugin/api/"

private class Rule(
    val capability: Capability,
    val method: ((MemberRef) -> Boolean)? = null,
    val type: ((String) -> Boolean)? = null,
    val superType: ((String) -> Boolean)? = null,
    val string: ((String) -> Boolean)? = null,
)

private fun method(
    owner: String,
    vararg names: String,
): (MemberRef) -> Boolean = { ref -> ref.owner == owner && (names.isEmpty() || names.any { ref.name == it }) }

private fun methodByPrefix(
    ownerPrefix: String,
    namePrefixes: List<String>,
): (MemberRef) -> Boolean = { ref -> ref.owner.startsWith(ownerPrefix) && namePrefixes.any { ref.name.startsWith(it) } }

private fun typeIs(vararg names: String): (String) -> Boolean = { it in names }

private fun typeStartsWith(vararg prefixes: String): (String) -> Boolean = { t -> prefixes.any { t.startsWith(it) } }

/** The capabilities this scanner knows about, and how each is recognised in a class's constant pool. */
internal object CapabilityCatalog {
    private fun cap(
        id: String,
        risk: Risk,
        title: String,
        why: String,
    ) = Capability(id, risk, title, why)

    val processExec = cap("process.exec", Risk.HIGH, "Runs other programs", "Runtime.exec or ProcessBuilder starts an OS process with the user's rights.")
    val netClient = cap("net.client", Risk.MEDIUM, "Opens outbound network connections", "Can send data off the machine.")
    val netListen = cap("net.listen", Risk.HIGH, "Listens for inbound connections", "Opens a port other software on the machine or network can reach.")
    val fsWrite = cap("fs.write", Risk.MEDIUM, "Writes files", "Can create or change files outside the plugin's own storage.")
    val fsDelete = cap("fs.delete", Risk.MEDIUM, "Deletes or moves files", "Can remove or relocate user files.")
    val fsRead = cap("fs.read", Risk.LOW, "Reads files", "Ordinary, but combined with a network capability it is how data leaves.")
    val reflectUse = cap("reflect.use", Risk.LOW, "Uses reflection", "Calls code by name, which static analysis cannot follow.")
    val reflectAccess = cap("reflect.access", Risk.MEDIUM, "Bypasses access checks", "setAccessible or Unsafe reads and writes members that are private by design.")
    val unsafe = cap("reflect.unsafe", Risk.HIGH, "Uses sun.misc.Unsafe or JDK internals", "Raw memory access and internals that bypass the JVM's safety.")
    val dynClass = cap("dynamic.classload", Risk.HIGH, "Defines or loads classes at run time", "Code that is not in this JAR can run, so this scan cannot see all of it.")
    val dynScript = cap("dynamic.script", Risk.HIGH, "Compiles or evaluates code at run time", "A script engine or compiler runs text as code.")
    val nativeCode = cap("native.code", Risk.HIGH, "Loads native code", "Native libraries run outside the JVM's protections.")
    val envRead = cap("env.read", Risk.MEDIUM, "Reads environment variables", "BOSS keeps API keys in the environment and in ~/.boss/env_vars.")
    val jvmExit = cap("jvm.exit", Risk.MEDIUM, "Can stop the whole app", "System.exit or Runtime.halt ends the host, not just the plugin.")
    val robot = cap("input.robot", Risk.HIGH, "Synthesises input or captures the screen", "java.awt.Robot can type, click and read pixels in any application.")
    val sysClipboard = cap("clipboard.system", Risk.MEDIUM, "Reads the system clipboard", "Clipboards routinely hold passwords.")
    val credPath = cap("cred.path", Risk.MEDIUM, "Names a credential file", "The plugin mentions a path where tokens or keys are stored.")

    val hostSecrets = cap("host.secrets", Risk.HIGH, "Uses the secret vault API", "SecretDataProvider reaches the user's stored passwords.")
    val hostBrokered = cap("host.brokered-credential", Risk.HIGH, "Uses brokered credentials", "Receives short-lived keys minted for the signed-in user.")
    val hostStoreKey = cap("host.store-key", Risk.HIGH, "Uses the plugin store API key", "Can act against the plugin store as the app.")
    val hostSupabase = cap("host.supabase", Risk.HIGH, "Uses the authenticated backend proxy", "SupabaseDataProvider sends queries with the user's session attached.")
    val hostAdmin = cap("host.admin", Risk.HIGH, "Manages users or roles", "RoleManagementProvider and UserManagementProvider change who can do what.")
    val hostProjectReplace = cap("host.project-replace", Risk.HIGH, "Rewrites files across the open project", "ProjectSearchProvider.replaceInProject is ungated: no permission stands between a plugin and the write.")
    val hostProjectSearch = cap("host.project-search", Risk.MEDIUM, "Searches the open project", "Reads the content of every file in the project.")
    val hostFiles = cap("host.filesystem", Risk.MEDIUM, "Uses the host file system API", "Reads and writes files through the host.")
    val hostEventBus = cap("host.event-bus", Risk.MEDIUM, "Subscribes to the application event bus", "The bus is ungated: every plugin sees browsing events and every project the user opens.")
    val hostBrowser = cap("host.browser", Risk.MEDIUM, "Drives the integrated browser", "Can read pages and act inside logged-in sessions.")
    val hostEditor = cap("host.editor", Risk.MEDIUM, "Reads editor content", "Sees the text of open files.")
    val hostClipboard = cap("host.clipboard", Risk.MEDIUM, "Uses the host clipboard API", "Clipboards routinely hold passwords.")
    val hostScreen = cap("host.screen-capture", Risk.MEDIUM, "Captures the screen", "Screenshots show whatever is open.")
    val hostLlm = cap("host.llm", Risk.MEDIUM, "Spends the user's AI credentials", "LlmProvider makes model calls on the user's keys.")
    val hostTabs = cap("host.active-tabs", Risk.MEDIUM, "Reads open tabs in every window", "Tab titles and URLs describe what the user is doing.")
    val hostMcp = cap("host.mcp", Risk.MEDIUM, "Exposes tools to AI agents", "Registered MCP tools are callable by any agent connected to BOSS.")
    val hostAuth = cap("host.auth", Risk.LOW, "Reads the signed-in identity", "Learns who the user is.")
    val hostGit = cap("host.git", Risk.LOW, "Uses the git API", "Reads repository state.")

    /** Pairs of (capability id, host provider type it is recognised by). Also read by the drift test. */
    internal val hostTypes: Map<Capability, List<String>> =
        mapOf(
            hostSecrets to listOf("${API}SecretDataProvider"),
            hostBrokered to listOf("${API}BrokeredCredentialProvider"),
            hostStoreKey to listOf("${API}PluginStoreApiKeyProvider"),
            hostSupabase to listOf("${API}SupabaseDataProvider"),
            hostAdmin to listOf("${API}RoleManagementProvider", "${API}UserManagementProvider"),
            hostProjectSearch to listOf("${API}ProjectSearchProvider"),
            hostFiles to listOf("${API}FileSystemDataProvider"),
            hostEventBus to listOf("${API}ApplicationEventBus"),
            hostBrowser to listOf("ai/rever/boss/plugin/browser/BrowserService"),
            hostEditor to listOf("${API}EditorContentProvider"),
            hostClipboard to listOf("${API}ClipboardProvider"),
            hostScreen to listOf("${API}ScreenCaptureProvider"),
            hostLlm to listOf("${API}LlmProvider"),
            hostTabs to listOf("${API}ActiveTabsProvider"),
            hostAuth to listOf("${API}AuthDataProvider"),
            hostGit to listOf("${API}GitDataProvider"),
        )

    /** PluginContext getters the host API is reached through, by capability. Also read by the drift test. */
    internal val contextGetters: Map<Capability, List<String>> =
        mapOf(
            hostSecrets to listOf("getSecretDataProvider"),
            hostBrokered to listOf("getBrokeredCredentialProvider"),
            hostStoreKey to listOf("getPluginStoreApiKeyProvider"),
            hostSupabase to listOf("getSupabaseDataProvider"),
            hostAdmin to listOf("getRoleManagementProvider", "getUserManagementProvider"),
            hostProjectSearch to listOf("getProjectSearchProvider"),
            hostFiles to listOf("getFileSystemDataProvider"),
            hostEventBus to listOf("getApplicationEventBus"),
            hostBrowser to listOf("getBrowserService"),
            hostEditor to listOf("getEditorContentProvider"),
            hostClipboard to listOf("getClipboardProvider"),
            hostScreen to listOf("getScreenCaptureProvider"),
            hostLlm to listOf("getLlmProvider"),
            hostTabs to listOf("getActiveTabsProvider"),
            hostAuth to listOf("getAuthDataProvider"),
            hostGit to listOf("getGitDataProvider"),
        )

    private val credentialPathMarkers =
        listOf(".ssh/", ".ssh\\", "id_rsa", "id_ed25519", ".aws/credentials", ".npmrc", ".git-credentials", ".netrc", "env_vars")

    private val rules: List<Rule> =
        buildList {
            add(Rule(processExec, method = method("java/lang/Runtime", "exec")))
            add(Rule(processExec, method = method("java/lang/ProcessBuilder", "<init>", "start", "command")))
            add(Rule(netClient, method = { it.owner in NET_CLIENT_TYPES && it.name != "toString" }))
            add(Rule(netClient, type = typeStartsWith("io/ktor/client/", "okhttp3/", "org/apache/http/client/")))
            add(Rule(netListen, method = method("java/net/ServerSocket", "<init>", "bind", "accept")))
            add(Rule(netListen, method = method("java/nio/channels/ServerSocketChannel", "open", "bind")))
            add(Rule(netListen, type = typeStartsWith("io/ktor/server/", "com/sun/net/httpserver/")))
            add(Rule(fsWrite, method = { FS_WRITERS.contains(it.owner to it.name) }))
            add(Rule(fsWrite, method = methodByPrefix("kotlin/io/FilesKt", listOf("writeText", "writeBytes", "appendText", "appendBytes", "copyTo", "copyRecursively"))))
            add(Rule(fsDelete, method = { FS_DELETERS.contains(it.owner to it.name) }))
            add(Rule(fsDelete, method = methodByPrefix("kotlin/io/FilesKt", listOf("deleteRecursively"))))
            add(Rule(fsRead, method = { FS_READERS.contains(it.owner to it.name) }))
            add(Rule(fsRead, method = methodByPrefix("kotlin/io/FilesKt", listOf("readText", "readBytes", "readLines", "walk", "useLines"))))
            add(Rule(fsRead, method = methodByPrefix("kotlin/io/FilesKt", listOf("inputStream", "bufferedReader", "reader"))))
            add(Rule(fsRead, method = method("java/util/zip/ZipFile", "<init>")))
            add(Rule(fsRead, method = method("java/util/jar/JarFile", "<init>")))
            add(Rule(reflectUse, method = method("java/lang/Class", "forName")))
            add(Rule(reflectUse, method = method("java/lang/reflect/Method", "invoke")))
            add(Rule(reflectUse, method = method("java/lang/reflect/Constructor", "newInstance")))
            add(Rule(reflectAccess, method = { it.name == "setAccessible" || it.name == "trySetAccessible" }))
            add(Rule(unsafe, type = typeStartsWith("sun/misc/Unsafe", "jdk/internal/", "sun/reflect/")))
            add(Rule(dynClass, method = method("java/lang/ClassLoader", "defineClass")))
            add(Rule(dynClass, method = method("java/net/URLClassLoader", "<init>", "newInstance")))
            add(Rule(dynClass, superType = typeIs("java/lang/ClassLoader", "java/net/URLClassLoader", "java/security/SecureClassLoader")))
            add(Rule(dynClass, method = method("java/lang/invoke/MethodHandles\$Lookup", "defineClass", "defineHiddenClass")))
            add(Rule(dynScript, type = typeStartsWith("javax/script/", "javax/tools/", "groovy/lang/", "org/mozilla/javascript/")))
            add(Rule(nativeCode, method = method("java/lang/System", "load", "loadLibrary")))
            add(Rule(nativeCode, method = method("java/lang/Runtime", "load", "loadLibrary")))
            add(Rule(nativeCode, type = typeStartsWith("com/sun/jna/", "java/lang/foreign/", "jdk/incubator/foreign/")))
            add(Rule(envRead, method = method("java/lang/System", "getenv")))
            add(Rule(envRead, method = method("java/lang/ProcessBuilder", "environment")))
            add(Rule(jvmExit, method = method("java/lang/System", "exit")))
            add(Rule(jvmExit, method = method("java/lang/Runtime", "exit", "halt")))
            add(Rule(robot, type = typeIs("java/awt/Robot")))
            add(Rule(sysClipboard, method = method("java/awt/Toolkit", "getSystemClipboard")))
            add(Rule(credPath, string = { s -> credentialPathMarkers.any { s.contains(it) } }))
            for ((capability, types) in hostTypes) add(Rule(capability, type = typeIs(*types.toTypedArray())))
            for ((capability, getters) in contextGetters) {
                add(Rule(capability, method = { it.owner == "${API}PluginContext" && it.name in getters }))
            }
            add(Rule(hostProjectReplace, method = { it.owner == "${API}ProjectSearchProvider" && it.name.startsWith("replaceInProject") }))
            add(Rule(hostMcp, method = { it.owner == "${API}PluginContext" && it.name == "registerMcpToolProvider" }))
            add(Rule(hostMcp, type = typeIs("${API}McpToolProvider")))
        }

    private val NET_CLIENT_TYPES =
        setOf(
            "java/net/Socket",
            "java/net/URL",
            "java/net/URLConnection",
            "java/net/HttpURLConnection",
            "java/net/DatagramSocket",
            "java/net/http/HttpClient",
            "java/nio/channels/SocketChannel",
            "javax/net/ssl/HttpsURLConnection",
        )

    private val FS_WRITERS =
        setOf(
            "java/io/FileOutputStream" to "<init>",
            "java/io/FileWriter" to "<init>",
            "java/io/RandomAccessFile" to "<init>",
            "java/nio/file/Files" to "write",
            "java/nio/file/Files" to "writeString",
            "java/nio/file/Files" to "newOutputStream",
            "java/nio/file/Files" to "newBufferedWriter",
            "java/nio/file/Files" to "createFile",
            "java/nio/file/Files" to "copy",
            "java/nio/file/Files" to "setPosixFilePermissions",
        )

    private val FS_DELETERS =
        setOf(
            "java/io/File" to "delete",
            "java/io/File" to "deleteOnExit",
            "java/io/File" to "renameTo",
            "java/nio/file/Files" to "delete",
            "java/nio/file/Files" to "deleteIfExists",
            "java/nio/file/Files" to "move",
            "java/nio/file/Files" to "walkFileTree",
        )

    private val FS_READERS =
        setOf(
            "java/io/FileInputStream" to "<init>",
            "java/io/FileReader" to "<init>",
            "java/nio/file/Files" to "readAllBytes",
            "java/nio/file/Files" to "readString",
            "java/nio/file/Files" to "readAllLines",
            "java/nio/file/Files" to "newInputStream",
            "java/nio/file/Files" to "newBufferedReader",
            "java/nio/file/Files" to "lines",
            "java/nio/file/Files" to "walk",
        )

    /** The complete list, for `xray_capabilities`. */
    val all: List<Capability> by lazy { rules.map { it.capability }.distinctBy { it.id }.sortedWith(compareByDescending<Capability> { it.risk }.thenBy { it.id }) }

    /** Every capability [info] references, with the first piece of evidence for each. */
    fun detect(info: ClassInfo): List<Hit> {
        val seen = LinkedHashMap<String, Hit>()
        fun hit(
            rule: Rule,
            detail: String,
        ) {
            seen.putIfAbsent(rule.capability.id, Hit(rule.capability, Evidence(info.name, detail)))
        }
        for (rule in rules) {
            rule.method?.let { m -> info.methodRefs.firstOrNull(m)?.let { hit(rule, "${it.owner}.${it.name}") } }
            rule.type?.let { t -> info.mentionedTypes.firstOrNull(t)?.let { hit(rule, it) } }
            rule.superType?.let { t -> (listOfNotNull(info.superName) + info.interfaces).firstOrNull(t)?.let { hit(rule, "extends $it") } }
            rule.string?.let { s -> info.strings.firstOrNull(s)?.let { hit(rule, "string constant") } }
        }
        return seen.values.toList()
    }
}
