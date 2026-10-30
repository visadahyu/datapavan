import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuiltArtifactsLoader
import java.util.zip.ZipFile
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Permissions that must never appear in the merged manifest. v0.1 is network-free by design;
// if any library tries to add one of these, the build fails instead of silently shipping it.
val forbiddenPermissions = listOf("android.permission.INTERNET")

// The JNI symbol every packaged libdatapavan.so must export (see core/jni and NativeCore.kt).
val requiredJniSymbol = "Java_org_visadahyu_datapavan_core_NativeCore_version"

android {
    namespace = "org.visadahyu.datapavan"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "org.visadahyu.datapavan"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0-dev"
        // The ABIs we ship: arm64 for real phones, x86_64 for the emulator and ChromeOS.
        // This list is the single source of truth; the Rust build reads it in finalizeDsl.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        debug {
            isPseudoLocalesEnabled = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    androidResources {
        generateLocaleConfig = true
        // Ship only the languages we translate. Without this, library translations for ~85
        // languages are bundled and the UI would mix languages on unsupported locales.
        localeFilters += listOf("en", "fr", "de", "fa")
    }

    // Google's encrypted dependency report is opaque to users and rejected by F-Droid.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        checkDependencies = true
        // These checks need network access and only say "a newer version exists".
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.startup.runtime)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    testImplementation(libs.junit)
}

/**
 * Builds the Rust JNI library for every shipped ABI with cargo-ndk.
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
        args += listOf("build", "--locked", "-p", "datapavan-jni")
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

/**
 * Builds the payload of the data pack (ADR 0015 and 0017, docs/DATA-PACKS.md) from `data/`: a header
 * with the sequence, date and keys from `data/PACK` and one line per file, then the files. Every
 * dataset goes in with its LICENSE, SOURCE and REUSE sidecar files, but not the scripts that produce
 * it. The APK carries the payload as `assets/data/bundled.payload`, and a published pack is the same
 * payload, signed. Files are sorted by path, so the same data always gives the same bytes.
 */
abstract class BundledDataTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val dataDir: DirectoryProperty

    /** Keys trusted in addition to those in `data/PACK`: the test key, in debug builds only. */
    @get:Input
    abstract val extraKeys: ListProperty<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val source = dataDir.get().asFile
        val fields = source.resolve("PACK").readLines()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { it.substringBefore(' ') to it.substringAfter(' ', "") }
        fun all(name: String) = fields.filter { it.first == name }.map { it.second }
        fun single(name: String, format: Regex) = all(name).singleOrNull()?.takeIf(format::matches)
            ?: throw GradleException("data/PACK needs one '$name' line matching $format")
        val unknown = fields.map { it.first }.toSet() - setOf("sequence", "date", "key", "revoked")
        if (unknown.isNotEmpty()) throw GradleException("data/PACK has unknown lines: $unknown")
        val key = Regex("RW[A-Za-z0-9+/]{54}")
        val keys = (all("key") + extraKeys.get()).distinct()
        val revoked = all("revoked")
        (keys + revoked).firstOrNull { !key.matches(it) }?.let { throw GradleException("data/PACK: not a signify public key: $it") }

        // The same rules as the Rust reader (core/engine/src/datapack.rs), checked here so that a
        // bad name fails the build rather than the app.
        val path = Regex("[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*")
        val files = source.walkTopDown()
            .filter { it.isFile && it.parentFile != source && it.extension !in setOf("py", "sh") && !it.name.startsWith(".") }
            .map { it.relativeTo(source).invariantSeparatorsPath to it }
            .sortedBy { it.first }
            .toList()
        files.firstOrNull { (name, _) -> !path.matches(name) || name.length > 128 }
            ?.let { throw GradleException("data/${it.first}: the name cannot go into a data pack") }

        val header = buildString {
            append("datapavan-data-pack 1\n")
            append("sequence ${single("sequence", Regex("[1-9][0-9]{0,8}"))}\n")
            append("date ${single("date", Regex("[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"))}\n")
            keys.forEach { append("key $it\n") }
            revoked.forEach { append("revoked $it\n") }
            files.forEach { (name, file) -> append("file $name ${file.length()}\n") }
            append("end\n")
        }
        outputDir.get().asFile.deleteRecursively()
        val target = outputDir.get().asFile.resolve("data/bundled.payload")
        target.parentFile.mkdirs()
        target.outputStream().use { out ->
            out.write(header.toByteArray(Charsets.US_ASCII))
            files.forEach { (_, file) -> file.inputStream().use { it.copyTo(out) } }
        }
    }
}

/**
 * Verifies the merged manifest and passes it on unchanged. Wired as a transform of
 * MERGED_MANIFEST, so every consumer (APK, bundle, install) depends on it and cannot bypass it.
 */
abstract class ForbiddenPermissionsCheck : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val forbidden: ListProperty<String>

    @get:OutputFile
    abstract val checkedManifest: RegularFileProperty

    @TaskAction
    fun verify() {
        val source = mergedManifest.get().asFile
        val text = source.readText()
        val found = forbidden.get().filter { permission ->
            Regex("""<uses-permission[^>]*android:name="${Regex.escape(permission)}"""").containsMatchIn(text)
        }
        if (found.isNotEmpty()) {
            throw GradleException("Forbidden permission(s) in the merged manifest: $found")
        }
        source.copyTo(checkedManifest.get().asFile, overwrite = true)
    }
}

/** Fails if a built APK lacks the Rust library for a shipped ABI, or if it does not export the JNI symbol. */
abstract class ApkNativeLibraryCheck : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:Internal
    abstract val loader: Property<BuiltArtifactsLoader>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val symbol: Property<String>

    @get:OutputFile
    abstract val report: RegularFileProperty

    @TaskAction
    fun verify() {
        val artifacts = loader.get().load(apkDirectory.get())
            ?: throw GradleException("No APK found in ${apkDirectory.get().asFile}")
        val lines = mutableListOf<String>()
        artifacts.elements.forEach { element ->
            ZipFile(element.outputFile).use { zip ->
                abis.get().forEach { abi ->
                    val entry = zip.getEntry("lib/$abi/libdatapavan.so")
                        ?: throw GradleException("${element.outputFile}: lib/$abi/libdatapavan.so is missing")
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    if (!String(bytes, Charsets.ISO_8859_1).contains(symbol.get())) {
                        throw GradleException("${element.outputFile}: lib/$abi/libdatapavan.so does not export ${symbol.get()}")
                    }
                    lines += "OK ${File(element.outputFile).name} lib/$abi/libdatapavan.so (${bytes.size} bytes)"
                }
            }
        }
        report.get().asFile.writeText(lines.joinToString("\n", postfix = "\n"))
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

// The data-signing test key (scripts/testdata), whose secret half is public: debug builds trust it so
// that imports can be tested, and release builds never do.
val testDataKey = providers.fileContents(repositoryRoot.file("scripts/testdata/datapack-test.pub"))
    .asText.map { it.lines()[1] }

// The payload of a pack to publish, without the test key; it is signed offline (docs/DATA-PACKS.md).
tasks.register<BundledDataTask>("dataPayload") {
    dataDir.set(repositoryRoot.dir("data"))
    extraKeys.set(emptyList())
    outputDir.set(layout.buildDirectory.dir("datapack"))
}

var shippedAbis: List<String> = emptyList()

androidComponents {
    finalizeDsl { extension ->
        shippedAbis = extension.defaultConfig.ndk.abiFilters.sorted()
        extension.buildTypes.forEach { buildType ->
            check(buildType.ndk.abiFilters.isEmpty()) {
                "Set ABIs only in defaultConfig.ndk.abiFilters; build type '${buildType.name}' overrides them."
            }
        }
    }

    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar(Char::uppercase)

        val cargoTask = tasks.register<CargoNdkTask>("cargoNdk$suffix") {
            sources.from(fileTree(rustWorkspace) { exclude("target/**", "fuzz/**") })
            sources.from(rootProject.layout.projectDirectory.file("../rust-toolchain.toml"))
            workspaceDir.set(rustWorkspace)
            abis.set(shippedAbis)
            platformLevel.set(variant.minSdk.apiLevel)
            release.set(variant.buildType == "release")
            cargo.set(cargoExecutable)
            cargoNdkVersion.set(cargoNdkVersionProvider)
            ndkPath.set(androidComponents.sdkComponents.ndkDirectory.map { it.asFile.absolutePath })
            rustFlags.set(remappedRustFlags)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoTask, CargoNdkTask::outputDir)

        val dataTask = tasks.register<BundledDataTask>("bundledData$suffix") {
            dataDir.set(repositoryRoot.dir("data"))
            extraKeys.set(if (variant.buildType == "debug") testDataKey.map(::listOf) else provider { emptyList() })
        }
        variant.sources.assets?.addGeneratedSourceDirectory(dataTask, BundledDataTask::outputDir)

        val permissionCheck = tasks.register<ForbiddenPermissionsCheck>("checkPermissions$suffix") {
            forbidden.set(forbiddenPermissions)
        }
        variant.artifacts.use(permissionCheck)
            .wiredWithFiles(ForbiddenPermissionsCheck::mergedManifest, ForbiddenPermissionsCheck::checkedManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)

        tasks.register<ApkNativeLibraryCheck>("verifyApk$suffix") {
            apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
            loader.set(variant.artifacts.getBuiltArtifactsLoader())
            abis.set(shippedAbis)
            symbol.set(requiredJniSymbol)
            report.set(layout.buildDirectory.file("reports/apk-native/${variant.name}.txt"))
        }
    }
}
