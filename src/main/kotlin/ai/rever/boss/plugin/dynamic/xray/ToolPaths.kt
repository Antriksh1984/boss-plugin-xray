package ai.rever.boss.plugin.dynamic.xray

import java.io.File

/**
 * Decides whether a path an agent supplied may be opened at all, from its text alone.
 *
 * On Windows the first filesystem call against `\\host\share\x` (an existence check, a length, an open)
 * makes the OS connect to `host` and authenticate as the signed-in user, so a tool that stats a path
 * before looking at it hands a stranger's server the user's NTLM response. The tool argument comes from an
 * agent that may itself be repeating text from a web page, so the text is checked first and the
 * filesystem only afterwards. Applies on Windows only: elsewhere `//x` is an ordinary path.
 */
internal object ToolPaths {
    private const val MAX_PATH_CHARS = 4096

    sealed interface Verdict {
        data class Ok(
            val file: File,
        ) : Verdict

        data class Refused(
            val reason: String,
        ) : Verdict
    }

    private val deviceOrUncPrefixes = listOf("\\\\?\\", "\\\\.\\", "\\??\\")

    fun isNetworkPath(
        path: String,
        windows: Boolean = System.getProperty("os.name").lowercase().contains("windows"),
    ): Boolean {
        if (!windows) return false
        val s = path.trimStart { it.isWhitespace() || it.isISOControl() }.replace('/', '\\')
        val device = deviceOrUncPrefixes.firstOrNull { s.startsWith(it) }
        if (device != null) {
            val rest = s.substring(device.length)
            val local = Regex("^([A-Za-z]:(\\\\|$)|Volume\\{[0-9A-Fa-f-]+\\})").containsMatchIn(rest)
            return !local
        }
        return s.startsWith("\\\\")
    }

    fun check(
        path: String?,
        windows: Boolean = System.getProperty("os.name").lowercase().contains("windows"),
    ): Verdict {
        val refusal =
            when {
                path.isNullOrBlank() -> "Missing required argument: path"
                path.length > MAX_PATH_CHARS -> "path is longer than $MAX_PATH_CHARS characters"
                path.contains(0.toChar()) -> "path contains a NUL byte"
                isNetworkPath(path, windows) -> "path names a network location; copy the JAR to a local folder first"
                !path.endsWith(".jar", ignoreCase = true) -> "path must be a .jar file"
                else -> null
            }
        if (refusal != null) return Verdict.Refused(refusal)
        val file = File(path).absoluteFile
        return when {
            !file.isFile -> Verdict.Refused("no such file")
            file.length() > JarScanner.MAX_JAR_BYTES -> Verdict.Refused("file is larger than ${JarScanner.MAX_JAR_BYTES} bytes")
            else -> Verdict.Ok(file)
        }
    }
}
