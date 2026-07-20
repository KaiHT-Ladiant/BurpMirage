plugins {
    java
}

group = "com.burpmirage"
version = "1.0.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    implementation("com.google.code.gson:gson:2.11.0")
}

fun configureLocaleJar(locale: String, classifier: String): org.gradle.api.tasks.bundling.Jar {
    val taskName = "jar${classifier.replaceFirstChar { it.uppercase() }}"
    return tasks.register<Jar>(taskName) {
        group = "build"
        description = "Build BurpMirage JAR with $locale UI strings"
        archiveBaseName.set("burpmirage")
        archiveClassifier.set(classifier)
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE

        dependsOn(tasks.classes)

        from(sourceSets.main.get().output)
        from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
        from("src/i18n/messages_${locale}.properties") {
            into("i18n")
            rename { "messages.properties" }
        }

        // Bundle the standalone Frida bridge (frida embedded) so the JAR is a
        // single self-contained file — no separate exe / Python needed.
        // Built via: packaging\build_bridge_exe.bat  ->  dist\burpmirage-bridge.exe
        val bridgeExe = layout.projectDirectory.file("dist/burpmirage-bridge.exe").asFile
        if (bridgeExe.exists()) {
            from(bridgeExe) { into("frida") }
        }

        manifest {
            attributes(
                "Implementation-Title" to "BurpMirage",
                "Implementation-Version" to version,
                "Burp-Extension-Name" to "BurpMirage",
                "BurpMirage-Locale" to locale,
            )
        }
    }.get()
}

tasks.named<Jar>("jar") {
    enabled = false
}

val jarEn = configureLocaleJar("en", "en")
val jarKo = configureLocaleJar("ko", "ko")

tasks.named("build") {
    dependsOn(jarEn, jarKo)
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
