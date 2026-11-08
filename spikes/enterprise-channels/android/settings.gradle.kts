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

rootProject.name = "enterprise-channels-spike"
include(":controller", ":probe")
