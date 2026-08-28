// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

plugins {
    id("com.android.application")
}

android {
    namespace = "dev.zygveil.location.controller"
    enableKotlin = false
    // The controller shares the exact Android 16 device boundary with the location module.
    //noinspection GradleDependency
    compileSdk = 36
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "dev.zygveil.location.controller"
        minSdk = 36
        //noinspection OldTargetApi
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        getByName("debug") {
            storeFile =
                file(
                    System.getenv("ZYGVEIL_KEYSTORE")
                        ?: rootProject.file(".container-input/debug.keystore"),
                )
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

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable.clear()
    }
}
