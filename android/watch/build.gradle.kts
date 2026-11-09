import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuiltArtifactsLoader
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Datapavan Watch (ADR 0029): the VPN, built from the same repository as the audit app and signed with
// the same key. Its merged manifest may hold only what ADR 0034 allows, so that no library adds a
// permission, an app query or an open door unnoticed: the permissions it requests, the permissions it
// defines, its <queries> and its exported components. Fewer is fine; anything else fails the build.
val watchApplicationId = "org.visadahyu.datapavan.watch"
val allowedPermissions = mapOf(
    // name to the android:maxSdkVersion it must carry, or null for none
    "android.permission.INTERNET" to null,
    "android.permission.ACCESS_NETWORK_STATE" to null,
    // Only Android 10 and 11 need it, to follow the network under the tunnel (ADR 0034).
    "android.permission.CHANGE_NETWORK_STATE" to "30",
    "android.permission.POST_NOTIFICATIONS" to null,
    "android.permission.ACCESS_LOCAL_NETWORK" to null,
    // androidx.core defines it, app-internal, for its non-exported receivers.
    "$watchApplicationId.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" to null,
)
// The JNI symbol every packaged libdatapavan_watch.so must export (see core/watch-jni and Engine.kt).
val requiredJniSymbol = "Java_org_visadahyu_datapavan_watch_Engine_nativeStart"

val allowedPermissionDefinitions = listOf("$watchApplicationId.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
// Exported components, each with the permission that guards it ("" for none: the launcher, and the log
// interface of W5, which checks its caller's key at run time).
val allowedExported = mapOf(
    "$watchApplicationId.MainActivity" to "",
    "androidx.profileinstaller.ProfileInstallReceiver" to "android.permission.DUMP",
)

android {
    namespace = "org.visadahyu.datapavan.watch"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = watchApplicationId
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.2.0"
        // The audit app's ABIs (app/build.gradle.kts), read by the Rust build in finalizeDsl.
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
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
    }

    androidResources {
        // The table from address to organisation (ADR 0036) is read in place, which needs it stored.
        noCompress += "bin"
        generateLocaleConfig = true
        // The audit app's languages (ADR 0004, ADR 0030), and no library's others.
        localeFilters += listOf("en", "fr", "de", "fa", "ru", "zh-rCN", "es", "ar")
    }

    bundle {
        language {
            enableSplit = false
        }
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
 * Verifies the merged manifest against ADR 0034's allowlist and passes it on unchanged. Wired as a
 * transform of MERGED_MANIFEST, so every consumer (APK, bundle, install) depends on it and cannot
 * bypass it. It checks <uses-permission> and <uses-permission-sdk-23> (with their maxSdkVersion),
 * <permission> definitions (signature only), <queries> (the one launcher intent, nothing else) and
 * every exported component with the permission that guards it.
 */
abstract class ManifestAllowlistCheck : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val permissions: MapProperty<String, String>

    @get:Input
    abstract val definitions: ListProperty<String>

    @get:Input
    abstract val exported: MapProperty<String, String>

    @get:OutputFile
    abstract val checkedManifest: RegularFileProperty

    @TaskAction
    fun verify() {
        val androidNs = "http://schemas.android.com/apk/res/android"
        val source = mergedManifest.get().asFile
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(source)
        fun elements(tag: String) = document.getElementsByTagName(tag).let { nodes ->
            (0 until nodes.length).map { nodes.item(it) as org.w3c.dom.Element }
        }
        fun org.w3c.dom.Element.android(name: String) = getAttributeNS(androidNs, name)
        val problems = mutableListOf<String>()

        for (element in elements("uses-permission") + elements("uses-permission-sdk-23")) {
            val name = element.android("name")
            val maxSdk = element.android("maxSdkVersion")
            when {
                name !in permissions.get() -> problems += "requests $name"
                // A map cannot hold null, so "" means "no maxSdkVersion".
                maxSdk != permissions.get().getValue(name) -> problems += "requests $name with maxSdkVersion '$maxSdk'"
            }
        }
        for (element in elements("permission")) {
            val name = element.android("name")
            if (name !in definitions.get() || element.android("protectionLevel") != "signature") {
                problems += "defines $name (${element.android("protectionLevel")})"
            }
        }
        for (queries in elements("queries")) {
            val children = queries.childNodes.let { nodes -> (0 until nodes.length).map { nodes.item(it) } }
                .filterIsInstance<org.w3c.dom.Element>()
            for (child in children) {
                val actions = child.getElementsByTagName("action").let { n -> (0 until n.length).map { (n.item(it) as org.w3c.dom.Element).android("name") } }
                val categories = child.getElementsByTagName("category").let { n -> (0 until n.length).map { (n.item(it) as org.w3c.dom.Element).android("name") } }
                val launcher = child.tagName == "intent" && actions == listOf("android.intent.action.MAIN") &&
                    categories == listOf("android.intent.category.LAUNCHER") && child.getElementsByTagName("data").length == 0
                if (!launcher) problems += "queries <${child.tagName}> ${actions + categories}"
            }
        }
        for (tag in listOf("activity", "activity-alias", "service", "receiver", "provider")) {
            for (element in elements(tag).filter { it.android("exported") == "true" }) {
                val name = element.android("name")
                val guard = element.android("permission")
                if (exported.get()[name] != guard) problems += "exports $tag $name (permission '$guard')"
            }
        }
        if (problems.isNotEmpty()) {
            throw GradleException("Watch's merged manifest holds what ADR 0034 does not allow:\n  " + problems.joinToString("\n  "))
        }
        source.copyTo(checkedManifest.get().asFile, overwrite = true)
    }
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

/** Fails if a built APK lacks Watch's library for a shipped ABI, or if it does not export the JNI symbol. */
abstract class ApkNativeLibraryCheck : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:Internal
    abstract val loader: Property<BuiltArtifactsLoader>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val library: Property<String>

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
                    val entry = zip.getEntry("lib/$abi/${library.get()}")
                        ?: throw GradleException("${element.outputFile}: lib/$abi/${library.get()} is missing")
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    if (!String(bytes, Charsets.ISO_8859_1).contains(symbol.get())) {
                        throw GradleException("${element.outputFile}: lib/$abi/${library.get()} does not export ${symbol.get()}")
                    }
                    lines += "OK ${File(element.outputFile).name} lib/$abi/${library.get()} (${bytes.size} bytes)"
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

        tasks.register<ApkNativeLibraryCheck>("verifyApk$suffix") {
            apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
            loader.set(variant.artifacts.getBuiltArtifactsLoader())
            abis.set(shippedAbis)
            library.set("libdatapavan_watch.so")
            symbol.set(requiredJniSymbol)
            report.set(layout.buildDirectory.file("reports/apk-native/${variant.name}.txt"))
        }
        val manifestCheck = tasks.register<ManifestAllowlistCheck>("checkManifest$suffix") {
            permissions.set(allowedPermissions.mapValues { it.value ?: "" })
            definitions.set(allowedPermissionDefinitions)
            exported.set(allowedExported)
        }
        variant.artifacts.use(manifestCheck)
            .wiredWithFiles(ManifestAllowlistCheck::mergedManifest, ManifestAllowlistCheck::checkedManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)
    }
}
