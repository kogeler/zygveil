// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

plugins {
    id("com.android.application")
}

android {
    namespace = "dev.zygveil.module"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "dev.zygveil.module"
        minSdk = 36
        // Android 16 is the explicit compatibility boundary for this module.
        //noinspection OldTargetApi
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        getByName("debug") {
            storeFile = file(System.getenv("ZYGVEIL_KEYSTORE") ?: "../.container-input/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        resources.merges += "META-INF/xposed/*"
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable.clear()
    }
}

dependencies {
    implementation(project(":policy"))
    compileOnly("io.github.libxposed:api:102.0.0")
    compileOnly("io.github.libxposed:annotation:1.0.0")
    compileOnly("androidx.annotation:annotation:1.10.0")
    implementation("io.github.libxposed:service:102.0.0")
}
