package ai.rever.boss.plugin.dynamic.xray

import java.nio.ByteBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The class file is a stranger's input: it must end in a result or in [MalformedClassException], and nothing else. */
class ClassFileReaderTest {
    private val sample = Fixtures.bytes(ExecFixture::class.java)

    @Test
    fun `a real class reads back its name and the references it makes`() {
        val info = ClassFileReader.read(sample)
        assertEquals("ai/rever/boss/plugin/dynamic/xray/ExecFixture", info.name)
        assertEquals("java/lang/Object", info.superName)
        assertTrue(info.methodRefs.any { it.owner == "java/lang/Runtime" && it.name == "exec" })
        assertTrue(info.methodRefs.any { it.owner == "java/lang/ProcessBuilder" && it.name == "<init>" })
    }

    @Test
    fun `array class constants are reduced to their element type`() {
        val info = ClassFileReader.read(Fixtures.bytes(FileFixture::class.java))
        assertTrue(info.classRefs.none { it.startsWith("[") }, "${info.classRefs}")
    }

    @Test
    fun `descriptor types count as mentioned`() {
        assertEquals(listOf("java/lang/String", "java/io/File"), typesIn("(Ljava/lang/String;I[Ljava/io/File;)V"))
    }

    @Test
    fun `not a class file`() {
        assertFailsWith<MalformedClassException> { ClassFileReader.read(ByteArray(0)) }
        assertFailsWith<MalformedClassException> { ClassFileReader.read(ByteArray(64) { 7 }) }
        assertFailsWith<MalformedClassException> { ClassFileReader.read(byteArrayOf(0x50, 0x4b, 3, 4, 32, 110, 111, 116)) }
    }

    @Test
    fun `every truncation of a real class fails cleanly`() {
        for (length in 0 until sample.size) {
            try {
                ClassFileReader.read(sample.copyOf(length))
            } catch (_: MalformedClassException) {
                // expected: the only failure a caller has to handle
            }
        }
    }

    @Test
    fun `a pool that claims more entries than the file holds fails cleanly`() {
        val lying = sample.copyOf()
        ByteBuffer.wrap(lying).putShort(8, 0xFFFF.toShort())
        assertFailsWith<MalformedClassException> { ClassFileReader.read(lying) }
    }

    @Test
    fun `a string longer than the file fails without allocating what it claims`() {
        val bytes = ByteBuffer.allocate(64)
        bytes.putInt(0xCAFEBABE.toInt()).putShort(0).putShort(61).putShort(2)
        bytes.put(1).putShort(0xFFFF.toShort()) // a Utf8 entry claiming 65535 bytes in a 64-byte file
        assertFailsWith<MalformedClassException> { ClassFileReader.read(bytes.array()) }
    }

    @Test
    fun `an unknown constant pool tag fails cleanly`() {
        val bytes = ByteBuffer.allocate(32)
        bytes.putInt(0xCAFEBABE.toInt()).putShort(0).putShort(61).putShort(2).put(99)
        assertFailsWith<MalformedClassException> { ClassFileReader.read(bytes.array()) }
    }

    @Test
    fun `random damage to a real class never escapes as another exception`() {
        val random = Random(20260919)
        repeat(3000) {
            val damaged = sample.copyOf()
            repeat(1 + random.nextInt(8)) { damaged[random.nextInt(damaged.size)] = random.nextInt().toByte() }
            try {
                ClassFileReader.read(damaged)
            } catch (_: MalformedClassException) {
                // fine
            }
        }
    }
}
