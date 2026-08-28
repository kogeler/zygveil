// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

plugins {
    id("com.android.library")
}

android {
    namespace = "dev.zygveil.policy"
    // The production policy is deliberately bounded to the Android 16 public API.
    //noinspection GradleDependency
    compileSdk = 36
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 36
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
