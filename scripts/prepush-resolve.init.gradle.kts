// SPDX-License-Identifier: Apache-2.0
// Gradle's part of scripts/check.sh resolve and prepush: a task, prepushResolve, in every project, whose inputs are the
// external modules of every configuration Gradle can resolve there, so that running it resolves, and downloads where
// missing, each one, and builds nothing: the plugins' markers (resolved before any task: CI's flake of 2026-11-20, -23
// and -24), the libraries, the tests' classpaths, Kotlin's compiler and its plugins, lint's own jars. CI's build job runs
// it before its gates, with retries (check.sh resolve); the pre-push check runs it with --refresh-dependencies, which
// makes Gradle ask the repositories again for each module's metadata rather than trust its cache. Dependency
// verification (android/gradle/verification-metadata.xml) checks every artifact as in any build. Left out, since the
// build fetches them its own way: AAPT2's binary, and the Play SDK Index that lint reads.
//
// A project's own outputs are left out: Android's configurations need the consumer's attributes to choose among
// them, and they are no dependency from outside.
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

allprojects {
    tasks.register("prepushResolve") {
        description = "Resolves the external modules of every resolvable configuration (scripts/check.sh prepush)."
        // Configured when the task graph is made, after every plugin has added its configurations.
        val resolvable = configurations.filter { it.isCanBeResolved }
        for (configuration in resolvable) {
            inputs.files(
                configuration.incoming.artifactView {
                    componentFilter { it is ModuleComponentIdentifier }
                }.files,
            ).withPropertyName("resolved.${configuration.name}")
        }
        val count = resolvable.size
        doLast { if (count > 0) logger.quiet("$path: $count configurations resolved") }
    }
}
