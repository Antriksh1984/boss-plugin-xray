package ai.rever.boss.plugin.dynamic.xray

import java.nio.BufferUnderflowException
import java.nio.ByteBuffer

/** A member (method or field) a class refers to: the owner's internal name, the member name and its descriptor. */
internal data class MemberRef(
    val owner: String,
    val name: String,
    val descriptor: String,
)

/**
 * What a class file's constant pool says the class refers to.
 *
 * This is what the class MENTIONS, not what it does. A method reference in the pool means some code may
 * call it; nothing here proves a call is reached, and nothing here sees code that is loaded or built at
 * run time.
 */
internal class ClassInfo(
    val name: String,
    val superName: String?,
    val interfaces: List<String>,
    val methodRefs: Set<MemberRef>,
    val fieldRefs: Set<MemberRef>,
    val classRefs: Set<String>,
    val strings: Set<String>,
) {
    /** Every type the class names, whether as a class constant or inside a member descriptor. */
    val mentionedTypes: Set<String> by lazy {
        val out = HashSet<String>(classRefs)
        (methodRefs + fieldRefs).forEach { ref -> out += typesIn(ref.descriptor) }
        out
    }
}

/** A class file that could not be read. The reason is safe to show: it never echoes bytes from the file. */
internal class MalformedClassException(
    reason: String,
) : Exception(reason)

/**
 * Reads the constant pool of a `.class` file and nothing else.
 *
 * Deliberately not a bytecode parser and not built on a bytecode library: the constant pool already
 * names every class, method and field a class can reach directly, it is a flat table, and reading only it
 * keeps the parser small enough to be checked by eye. Everything is bounds-checked, because the input is
 * whatever a stranger put in a JAR: a truncated file, a pool that lies about its own size, and a string
 * that claims to be longer than the file all end in [MalformedClassException], never in a crash or an
 * unbounded allocation.
 */
internal object ClassFileReader {
    private const val MAGIC = 0xCAFEBABE.toInt()
    private const val MAX_STRINGS = 4096
    private const val MAX_STRING_CHARS = 512

    private const val UTF8 = 1
    private const val INTEGER = 3
    private const val FLOAT = 4
    private const val LONG = 5
    private const val DOUBLE = 6
    private const val CLASS = 7
    private const val STRING = 8
    private const val FIELDREF = 9
    private const val METHODREF = 10
    private const val INTERFACE_METHODREF = 11
    private const val NAME_AND_TYPE = 12
    private const val METHOD_HANDLE = 15
    private const val METHOD_TYPE = 16
    private const val DYNAMIC = 17
    private const val INVOKE_DYNAMIC = 18
    private const val MODULE = 19
    private const val PACKAGE = 20

    fun read(bytes: ByteArray): ClassInfo =
        try {
            parse(ByteBuffer.wrap(bytes))
        } catch (_: BufferUnderflowException) {
            throw MalformedClassException("class file ends inside the constant pool")
        } catch (_: IndexOutOfBoundsException) {
            throw MalformedClassException("constant pool index out of range")
        }

    private class Pool(
        size: Int,
    ) {
        val tag = IntArray(size)
        val a = IntArray(size)
        val b = IntArray(size)
        val utf8 = arrayOfNulls<String>(size)
    }

    private fun parse(buf: ByteBuffer): ClassInfo {
        if (buf.remaining() < 10 || buf.int != MAGIC) throw MalformedClassException("not a class file")
        buf.short // minor
        buf.short // major
        val count = buf.short.toInt() and 0xFFFF
        if (count < 1) throw MalformedClassException("empty constant pool")

        val pool = Pool(count)
        var i = 1
        while (i < count) {
            val tag = buf.get().toInt() and 0xFF
            pool.tag[i] = tag
            when (tag) {
                UTF8 -> {
                    val len = buf.short.toInt() and 0xFFFF
                    if (len > buf.remaining()) throw MalformedClassException("string longer than the file")
                    val raw = ByteArray(len)
                    buf.get(raw)
                    pool.utf8[i] = String(raw, Charsets.UTF_8)
                }
                INTEGER, FLOAT -> buf.int
                LONG, DOUBLE -> {
                    buf.long
                    i++ // a long or double takes two pool slots
                }
                CLASS, STRING, METHOD_TYPE, MODULE, PACKAGE -> pool.a[i] = buf.short.toInt() and 0xFFFF
                FIELDREF, METHODREF, INTERFACE_METHODREF, NAME_AND_TYPE, DYNAMIC, INVOKE_DYNAMIC -> {
                    pool.a[i] = buf.short.toInt() and 0xFFFF
                    pool.b[i] = buf.short.toInt() and 0xFFFF
                }
                METHOD_HANDLE -> {
                    buf.get()
                    pool.a[i] = buf.short.toInt() and 0xFFFF
                }
                else -> throw MalformedClassException("unknown constant pool tag $tag")
            }
            i++
        }

        buf.short // access flags
        val thisName = className(pool, buf.short.toInt() and 0xFFFF) ?: throw MalformedClassException("no class name")
        val superIdx = buf.short.toInt() and 0xFFFF
        val superName = if (superIdx == 0) null else className(pool, superIdx)
        val interfaceCount = buf.short.toInt() and 0xFFFF
        val interfaces =
            (0 until interfaceCount).mapNotNull { className(pool, buf.short.toInt() and 0xFFFF) }

        return collect(pool, count, thisName, superName, interfaces)
    }

    private fun collect(
        pool: Pool,
        count: Int,
        name: String,
        superName: String?,
        interfaces: List<String>,
    ): ClassInfo {
        val methods = LinkedHashSet<MemberRef>()
        val fields = LinkedHashSet<MemberRef>()
        val classes = LinkedHashSet<String>()
        val strings = LinkedHashSet<String>()
        for (i in 1 until count) {
            when (pool.tag[i]) {
                CLASS -> className(pool, i)?.let { classes += if (it.startsWith("[")) typesIn(it) else listOf(it) }
                METHODREF, INTERFACE_METHODREF -> memberRef(pool, i)?.let { methods += it }
                FIELDREF -> memberRef(pool, i)?.let { fields += it }
                STRING ->
                    if (strings.size < MAX_STRINGS) {
                        utf8(pool, pool.a[i])?.let { strings += it.take(MAX_STRING_CHARS) }
                    }
            }
        }
        return ClassInfo(name, superName, interfaces, methods, fields, classes, strings)
    }

    private fun utf8(
        pool: Pool,
        index: Int,
    ): String? = if (index in 1 until pool.utf8.size) pool.utf8[index] else null

    private fun className(
        pool: Pool,
        index: Int,
    ): String? =
        if (index in 1 until pool.tag.size && pool.tag[index] == CLASS) utf8(pool, pool.a[index]) else null

    private fun memberRef(
        pool: Pool,
        index: Int,
    ): MemberRef? {
        val owner = className(pool, pool.a[index]) ?: return null
        val nat = pool.b[index]
        if (nat !in 1 until pool.tag.size || pool.tag[nat] != NAME_AND_TYPE) return null
        val name = utf8(pool, pool.a[nat]) ?: return null
        val descriptor = utf8(pool, pool.b[nat]) ?: return null
        return MemberRef(owner, name, descriptor)
    }
}

private val DESCRIPTOR_TYPE = Regex("L([^;]+);")

/** The class types named in a method or field descriptor, in internal form (`java/lang/String`). */
internal fun typesIn(descriptor: String): List<String> = DESCRIPTOR_TYPE.findAll(descriptor).map { it.groupValues[1] }.toList()
