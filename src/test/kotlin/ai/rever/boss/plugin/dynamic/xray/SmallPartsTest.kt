package ai.rever.boss.plugin.dynamic.xray

import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MiniJsonTest {
    @Test
    fun `objects arrays strings numbers and literals`() {
        val v = MiniJson.parse("""{"a":[1,2.5,true,false,null],"b":{"c":"d"},"e":""}""").asObject()!!
        assertEquals(listOf(1.0, 2.5, true, false, null), v["a"])
        assertEquals("d", v["b"].asObject()!!["c"])
        assertEquals("", v["e"])
    }

    @Test
    fun `string escapes decode`() {
        assertEquals("a\nb\t\"c\"\\ A", MiniJson.parse("\"a\\nb\\t\\\"c\\\"\\\\ \\u0041\""))
    }

    @Test
    fun `malformed documents fail with JsonException only`() {
        for (bad in listOf("", "{", "{\"a\"}", "{\"a\":}", "[1,]", "tru", "\"unterminated", "{} trailing", "\"bad\\q\"", "\"\\u12\"", "-", "{1:2}")) {
            assertFailsWith<JsonException>(bad) { MiniJson.parse(bad) }
        }
    }

    @Test
    fun `a raw control character in a string is refused`() {
        assertFailsWith<JsonException> { MiniJson.parse("\"a" + 27.toChar() + "b\"") }
    }

    @Test
    fun `nesting and size are bounded`() {
        assertFailsWith<JsonException> { MiniJson.parse("[".repeat(500) + "]".repeat(500)) }
        assertFailsWith<JsonException> { MiniJson.parse("\"" + "a".repeat(1_000_001) + "\"") }
    }

    @Test
    fun `string list ignores anything that is not text`() {
        assertEquals(listOf("a", "b"), listOf("a", 1.0, "b", null).asStringList())
        assertEquals(emptyList(), "nope".asStringList())
    }
}

class SafeTextTest {
    @Test
    fun `line breaks controls and bidi overrides are shown as escapes`() {
        val esc = 27.toChar()
        val rlo = 0x202e.toChar()
        val out = SafeText.of("a\nb\rc\td${esc}e${rlo}f${0x7f.toChar()}${0x85.toChar()}")
        assertEquals("a\\nb\\rc\\td\\u001be\\u202ef\\u007f\\u0085", out)
    }

    @Test
    fun `ordinary text passes through and long text is cut`() {
        assertEquals("plain text, cafe", SafeText.of("plain text, cafe"))
        assertTrue(SafeText.of("x".repeat(500), max = 10).endsWith("..."))
        assertEquals(13, SafeText.of("x".repeat(500), max = 10).length)
    }
}

class ToolPathsTest {
    private val dir = createTempDirectory("xray-paths").toFile()

    private fun refused(
        path: String?,
        windows: Boolean = true,
    ) = (ToolPaths.check(path, windows) as? ToolPaths.Verdict.Refused)?.reason

    @Test
    fun `a network location is refused before the file system is touched`() {
        for (p in listOf("""\\evil.example\share\p.jar""", "//evil.example/share/p.jar", """\\?\UNC\evil.example\s\p.jar""", """\\.\GLOBALROOT\Device\Mup\evil\s\p.jar""", """  \\evil\s\p.jar""")) {
            assertTrue(refused(p)!!.contains("network"), "should refuse: $p")
        }
    }

    @Test
    fun `local paths are not mistaken for network ones`() {
        assertFalse(ToolPaths.isNetworkPath("""C:\Users\me\p.jar""", windows = true))
        assertFalse(ToolPaths.isNetworkPath("""\\?\C:\Users\me\p.jar""", windows = true))
        assertFalse(ToolPaths.isNetworkPath("//tmp/p.jar", windows = false))
    }

    @Test
    fun `missing blank odd and non-jar paths are refused with a reason`() {
        assertEquals("Missing required argument: path", refused(null))
        assertEquals("Missing required argument: path", refused("  "))
        assertTrue(refused("a\u0000.jar")!!.contains("NUL"))
        assertTrue(refused("x".repeat(5000) + ".jar")!!.contains("longer"))
        assertTrue(refused("notes.txt")!!.contains(".jar"))
        assertEquals("no such file", refused(dir.resolve("absent.jar").path))
    }

    @Test
    fun `an existing local jar is accepted`() {
        val jar = dir.resolve("real.jar").apply { writeBytes(ByteArray(3)) }
        assertNull(refused(jar.path))
        assertTrue(ToolPaths.check(jar.path, windows = true) is ToolPaths.Verdict.Ok)
    }
}
