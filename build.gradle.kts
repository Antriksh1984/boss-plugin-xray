import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.10"
}

group = "ai.rever.boss.plugin.dynamic"
version = "0.1.0" // the single source of truth; processResources syncs it into plugin.json

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}
kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// CI sets CI=true and downloads the api jar; locally it is fetched into deps/.
val bossPluginApiJar = "deps/boss-plugin-api-1.0.93.jar"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by the host at runtime (parent-first classloading), so compile-only.
    compileOnly(files(bossPluginApiJar))
    compileOnly("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    testImplementation(kotlin("test"))
    testImplementation(files(bossPluginApiJar))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
}

tasks.test {
    useJUnit()
    dependsOn("buildPluginJar")
    systemProperty("xray.pluginJar", layout.buildDirectory.file("libs/boss-plugin-xray-${version}.jar").get().asFile.absolutePath)
    systemProperty("xray.apiJar", layout.projectDirectory.file(bossPluginApiJar).asFile.absolutePath)
    systemProperty("xray.mainClasses", layout.buildDirectory.dir("classes/kotlin/main").get().asFile.absolutePath)
}

// The loadable plugin JAR: compiled classes + the plugin.json manifest. Nothing else is bundled: the
// host supplies Kotlin, coroutines and the plugin API.
tasks.register<Jar>("buildPluginJar") {
    archiveFileName.set("boss-plugin-xray-${version}.jar")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes(
            "Implementation-Title" to "BOSS Plugin X-Ray",
            "Implementation-Version" to version,
        )
    }
    from(sourceSets.main.get().output)
}

// Keep plugin.json's version in lockstep with the build version.
tasks.processResources {
    filesMatching("**/plugin.json") {
        filter { line ->
            line.replace(Regex(""""version"\s*:\s*"[^"]*""""), """"version": "$version"""")
        }
    }
}

tasks.build { dependsOn("buildPluginJar") }
