// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ZygVeil"

include(":location-controller", ":probe")
project(":location-controller").projectDir = file("components/location/controller")
project(":probe").projectDir = file("components/probe")
