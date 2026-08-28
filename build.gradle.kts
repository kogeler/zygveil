// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

import org.gradle.api.tasks.compile.JavaCompile

plugins {
    id("com.android.application") version "9.2.1" apply false
    id("com.diffplug.spotless") version "8.9.0"
}

val aapt2ForCache by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    aapt2ForCache("com.android.tools.build:aapt2:9.2.1-15009934:linux")
}

spotless {
    java {
        target(
            "components/location/controller/src/**/*.java",
            "components/probe/src/**/*.java",
            "components/server-vpn/runtime/**/*.java",
            "components/zygisk-host/bridge/**/*.java",
        )
        googleJavaFormat("1.29.0")
    }
    kotlinGradle {
        target("*.gradle.kts", "**/*.gradle.kts")
        targetExclude("deprecated/**")
        ktlint("1.8.0")
    }
    format("technicalText") {
        target(
            ".containerignore",
            ".editorconfig",
            ".gitignore",
            "*.properties",
            "Makefile",
            "mk/*.mk",
            "**/*.xml",
        )
        targetExclude("deprecated/**")
        trimTrailingWhitespace()
        endWithNewline()
    }
    format("documentationText") {
        target("*.md", "**/*.md")
        targetExclude("deprecated/**")
        trimTrailingWhitespace()
        endWithNewline()
    }
}

subprojects {
    tasks.withType<JavaCompile>().configureEach {
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }
}

tasks.register("resolveAllDependencies") {
    doLast {
        aapt2ForCache.incoming
            .artifactView { lenient(false) }
            .files.files
        allprojects.forEach { project ->
            project.configurations
                .filter { it.isCanBeResolved }
                .forEach { configuration ->
                    configuration.incoming
                        .artifactView { lenient(true) }
                        .files.files
                }
        }
    }
}
