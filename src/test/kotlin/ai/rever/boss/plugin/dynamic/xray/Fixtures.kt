@file:Suppress("unused", "UNUSED_VARIABLE")

package ai.rever.boss.plugin.dynamic.xray

import ai.rever.boss.plugin.api.PluginContext
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.ServerSocket
import java.net.URL
import java.nio.file.Files

/**
 * Real compiled classes for the scanner to read. Each one references exactly the API its name says and is
 * never run: the scanner reads constant pools, and these exist to put the right entries in them.
 */
class ExecFixture {
    fun run() {
        Runtime.getRuntime().exec("true")
        ProcessBuilder("true").start()
    }
}

class NetFixture {
    fun run() {
        URL("http://exfil.example.test/upload").openStream()
    }
}

class ListenFixture {
    fun run() {
        ServerSocket(0)
    }
}

class FileFixture {
    fun run(f: File) {
        f.delete()
        Files.write(f.toPath(), ByteArray(1))
        Files.readAllBytes(f.toPath())
    }
}

class ReflectFixture {
    fun run() {
        val c = Class.forName("java.lang.String")
        c.declaredFields.forEach { it.isAccessible = true }
    }
}

class NativeFixture {
    fun run() {
        System.loadLibrary("something")
    }
}

class EnvFixture {
    fun run(): String? = System.getenv("API_KEY")
}

class ExitFixture {
    fun run() {
        System.exit(3)
    }
}

class CredentialPathFixture {
    val where = "/home/user/.ssh/id_rsa"
}

class LoaderFixture : ClassLoader()

/** A long and a double in the pool take two slots each; the reference after them must still be found. */
class WideConstantsFixture {
    fun run(): Long {
        val a = 1234567890123L
        val b = 2.718281828
        val c = 9876543210987L
        Runtime.getRuntime().exec("true")
        return a + b.toLong() + c
    }
}

class HostApiFixture {
    fun run(ctx: PluginContext) {
        ctx.secretDataProvider
        ctx.applicationEventBus
        ctx.projectSearchProvider?.let { p ->
            runBlocking { p.replaceInProject("a", "b", emptyList(), false, false, false, false) }
        }
        ctx.registerMcpToolProvider(object : ai.rever.boss.plugin.api.McpToolProvider {
            override val providerId = "x"

            override fun tools() = emptyList<ai.rever.boss.plugin.api.McpToolDefinition>()
        })
    }
}

/** Touches nothing the catalogue cares about. */
class BenignFixture {
    fun run(): String = listOf("a", "b").map { it.uppercase() }.joinToString("-")
}

internal object Fixtures {
    fun bytes(cls: Class<*>): ByteArray =
        cls.classLoader.getResourceAsStream(cls.name.replace('.', '/') + ".class")!!.use { it.readBytes() }

    fun info(cls: Class<*>): ClassInfo = ClassFileReader.read(bytes(cls))

    /** The bytes of a class by internal name, for building JARs that hold inner classes too. */
    fun bytesOf(internalName: String): ByteArray =
        Fixtures::class.java.classLoader.getResourceAsStream("$internalName.class")!!.use { it.readBytes() }

    /** The class and its compiler-generated inner classes (lambdas, coroutine state machines), as a JAR would hold them. */
    fun withInner(cls: Class<*>): List<ClassInfo> {
        val dir = java.io.File(cls.protectionDomain.codeSource.location.toURI()).resolve(cls.packageName.replace('.', '/'))
        val prefix = cls.simpleName + "$"
        val inner = dir.listFiles { f -> f.name.startsWith(prefix) && f.extension == "class" }.orEmpty().sortedBy { it.name }
        return listOf(info(cls)) + inner.map { ClassFileReader.read(it.readBytes()) }
    }

    fun ids(cls: Class<*>): Set<String> = withInner(cls).flatMap { CapabilityCatalog.detect(it) }.map { it.capability.id }.toSet()
}
