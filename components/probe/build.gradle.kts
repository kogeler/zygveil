// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

plugins {
    id("com.android.application")
}

android {
    namespace = "dev.zygveil.probe"
    // The probe must compile only against the Android 16 public SDK surface.
    //noinspection GradleDependency
    compileSdk = 36
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "dev.zygveil.probe"
        minSdk = 36
        // Android 16 is the explicit public detector boundary.
        //noinspection OldTargetApi
        targetSdk = 36
        versionCode = 1
        versionName = "0.2-probe"
    }

    flavorDimensions += "identity"
    productFlavors {
        create("primary") {
            dimension = "identity"
            applicationIdSuffix = ".primary"
            buildConfigField("String", "PROBE_VARIANT", "\"primary\"")
        }
        create("canary") {
            dimension = "identity"
            applicationIdSuffix = ".canary"
            buildConfigField("String", "PROBE_VARIANT", "\"canary\"")
        }
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

    buildFeatures {
        buildConfig = true
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

dependencies {
    add("canaryImplementation", "com.google.android.gms:play-services-location:21.4.0")
    add("canaryCompileOnly", "org.checkerframework:checker-qual:4.1.0")
}
