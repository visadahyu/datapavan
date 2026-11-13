import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.compose)
}

// Watch (ADR 0029, ADR 0045): the tunnel, its log and the chain, as a library that only Datapavan Advanced
// includes, so that Datapavan Basic never carries the Rust engine or a reason to hold INTERNET. The
// application's build (app/build.gradle.kts) checks the merged manifest of each edition against its own
// allowlist, and that Advanced's APK holds this library's native code and keeps the methods it calls back.
android {
    namespace = "org.visadahyu.datapavan.watch"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        minSdk = 29
        // The application's ABIs (app/build.gradle.kts), read by the Rust build in finalizeDsl.
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        // The methods the Rust library calls back by name, which R8 must keep in the application.
        consumerProguardFiles("proguard-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        // These checks need network access and only say "a newer version exists".
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
    }
}

dependencies {
    implementation(project(":shared"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.startup.runtime)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    testImplementation(libs.junit)
}

/**
 * Builds Watch's Rust JNI library (`core/watch-jni`) for every shipped ABI with cargo-ndk: the audit
 * app's task (app/build.gradle.kts), with the crate as an input.
 *
 * The cargo environment is controlled: inherited flags that could change the output are dropped, and
 * absolute paths (the cargo registry, the workspace) are remapped, so the library neither leaks the
 * builder's home directory nor differs between machines.
 */
abstract class CargoNdkTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val workspaceDir: DirectoryProperty

    @get:Input
    abstract val crate: Property<String>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val platformLevel: Property<Int>

    @get:Input
    abstract val release: Property<Boolean>

    @get:Input
    abstract val cargo: Property<String>

    @get:Input
    abstract val cargoNdkVersion: Property<String>

    @get:Input
    abstract val ndkPath: Property<String>

    @get:Input
    abstract val rustFlags: ListProperty<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        val args = mutableListOf(cargo.get(), "ndk")
        abis.get().forEach { args += listOf("-t", it) }
        args += listOf("--platform", platformLevel.get().toString(), "-o", out.absolutePath)
        args += listOf("build", "--locked", "-p", crate.get())
        if (release.get()) args += "--release"

        val dropped = setOf(
            "RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR",
        )
        val environment = System.getenv().filterKeys { it !in dropped && !it.startsWith("CARGO_PROFILE_") } +
            mapOf(
                "ANDROID_NDK_HOME" to ndkPath.get(),
                "CARGO_ENCODED_RUSTFLAGS" to rustFlags.get().joinToString("\u001f"),
            )
        execOperations.exec {
            workingDir = workspaceDir.get().asFile
            setEnvironment(environment)
            commandLine(args)
        }
    }
}

val repositoryRoot = rootProject.layout.projectDirectory.dir("..")
val rustWorkspace = rootProject.layout.projectDirectory.dir("../core")
val cargoHome = providers.environmentVariable("CARGO_HOME")
    .orElse(providers.systemProperty("user.home").map { "$it/.cargo" })
val cargoExecutable = providers.environmentVariable("CARGO")
    .orElse(cargoHome.map { home -> File(home, "bin/cargo").let { if (it.canExecute()) it.path else "cargo" } })
val cargoNdkVersionProvider = providers.exec { commandLine(cargoExecutable.get(), "ndk", "--version") }
    .standardOutput.asText.map { it.trim() }
val remappedRustFlags = cargoHome.map { home ->
    listOf(
        "--remap-path-prefix=$home/registry/src=/cargo/registry/src",
        "--remap-path-prefix=${repositoryRoot.asFile.absolutePath}=/datapavan",
    )
}

/** Copies the table of tools (data/tools, W6) into the assets, for Watch to find the user's tool. */
abstract class ToolTable : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val table: RegularFileProperty

    /** data/app-signers' apps.tsv, signers.tsv and SOURCE: the official keys of the tools (ADR 0018). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val signers: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        table.get().asFile.copyTo(out.resolve("tools.tsv"))
        signers.files.forEach { it.copyTo(out.resolve("app-signers/${it.name}")) }
    }
}

/** Copies the table from address to organisation into the assets, when there is one. */
abstract class OrganisationTable : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val table: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        table.files.singleOrNull()?.takeIf { it.isFile }?.copyTo(out.resolve("asn.bin"))
    }
}

var shippedAbis: List<String> = emptyList()

androidComponents {
    finalizeDsl { extension ->
        shippedAbis = extension.defaultConfig.ndk.abiFilters.sorted()
    }

    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar(Char::uppercase)

        val cargoTask = tasks.register<CargoNdkTask>("cargoNdk$suffix") {
            sources.from(fileTree(rustWorkspace) { exclude("target/**", "fuzz/**") })
            sources.from(rootProject.layout.projectDirectory.file("../rust-toolchain.toml"))
            // Tables compiled into the engine: the resolvers (core/net/src/resolvers.rs) and the
            // networks' owners (core/net/src/owners.rs).
            sources.from(repositoryRoot.file("data/resolvers/resolvers.tsv"))
            sources.from(repositoryRoot.file("data/owners/asns.tsv"), repositoryRoot.file("data/owners/entities.tsv"))
            workspaceDir.set(rustWorkspace)
            crate.set("datapavan-watch-jni")
            abis.set(shippedAbis)
            platformLevel.set(variant.minSdk.apiLevel)
            // -Pdatapavan.rustRelease=true: optimised Rust in a debug build too, so that the CPU check
            // (scripts/watch-lab/measure.sh) measures the engine as it ships, with the debug build's
            // test entry.
            release.set(variant.buildType == "release" || providers.gradleProperty("datapavan.rustRelease").orNull == "true")
            cargo.set(cargoExecutable)
            cargoNdkVersion.set(cargoNdkVersionProvider)
            ndkPath.set(androidComponents.sdkComponents.ndkDirectory.map { it.asFile.absolutePath })
            rustFlags.set(remappedRustFlags)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoTask, CargoNdkTask::outputDir)

        // The table from address to organisation, if data/dbip-asn/update.py has built one; it is not
        // committed until ADR 0036's size question is settled, so a clean checkout builds without it.
        val tableTask = tasks.register<OrganisationTable>("organisationTable$suffix") {
            table.from(repositoryRoot.file("data/dbip-asn/asn.bin"))
        }
        variant.sources.assets?.addGeneratedSourceDirectory(tableTask, OrganisationTable::outputDir)

        val toolsTask = tasks.register<ToolTable>("toolTable$suffix") {
            table.set(repositoryRoot.file("data/tools/tools.tsv"))
            signers.from(listOf("apps.tsv", "signers.tsv", "SOURCE").map { repositoryRoot.file("data/app-signers/$it") })
        }
        variant.sources.assets?.addGeneratedSourceDirectory(toolsTask, ToolTable::outputDir)
    }
}
