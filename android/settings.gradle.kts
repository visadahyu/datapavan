// Dependency-confusion guard: groups published by Google may come ONLY from Google's repository
// (exclusiveContent), and every other group comes from Maven Central. No other repository is used.
pluginManagement {
    repositories {
        exclusiveContent {
            forRepository { google() }
            filter {
                includeGroupByRegex("androidx(\\..+)?")
                includeGroupByRegex("com\\.android(\\..+)?")
                includeGroupByRegex("com\\.google\\.android(\\..+)?")
                includeGroupByRegex("com\\.google\\.testing\\.platform")
            }
        }
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        exclusiveContent {
            forRepository { google() }
            filter {
                includeGroupByRegex("androidx(\\..+)?")
                includeGroupByRegex("com\\.android(\\..+)?")
                includeGroupByRegex("com\\.google\\.android(\\..+)?")
                includeGroupByRegex("com\\.google\\.testing\\.platform")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "datapavan"
// The one application (ADR 0045): Datapavan Basic, or Datapavan Advanced with -Pdatapavan.edition=advanced.
include(":app")
// Code every edition shares: the rules that judge a copy's signing key, and the screen protection.
include(":shared")
// Watch's tunnel, log and chain: a library that only Advanced includes, so Basic never carries it.
include(":watch")
