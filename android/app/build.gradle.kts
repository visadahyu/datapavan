import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuiltArtifactsLoader
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The edition (ADR 0045; ADR 0031 for Google Play), chosen with -Pdatapavan.edition:
// - "basic", the default: Datapavan Basic, which never has network access;
// - "lite": Datapavan Basic for Google Play, under its own package, which Google signs;
// - "advanced": Datapavan Advanced, which adds Watch's tunnel, log and chain (the :watch library).
// A property rather than a product flavour, so that every task, output path and recipe (F-Droid,
// scripts/reproducible.sh, CI) still builds Basic exactly as before.
val edition = providers.gradleProperty("datapavan.edition").orNull ?: "basic"
check(edition in setOf("basic", "lite", "advanced")) { "-Pdatapavan.edition is basic, lite or advanced, not '$edition'" }
val editionName = edition
val lite = edition == "lite"
val advanced = edition == "advanced"
val editionApplicationId = when (edition) {
    "lite" -> "org.visadahyu.datapavan.lite"
    "advanced" -> "org.visadahyu.datapavan.advanced"
    else -> "org.visadahyu.datapavan"
}

// Advanced builds in a directory of its own, so that switching editions rebuilds nothing of the other's,
// and Basic's outputs stay where every script and recipe looks for them. Each edition also keeps a task
// history of its own (Gradle's project cache): with one history, a task that runs again for one edition
// deletes the outputs it made for the other, such as the other edition's APK.
if (advanced) layout.buildDirectory.set(layout.projectDirectory.dir("build-advanced"))
val advancedCache = ".gradle-advanced"
check((gradle.startParameter.projectCacheDir?.name == advancedCache) == advanced) {
    if (advanced) "Build Advanced with --project-cache-dir $advancedCache, so that it keeps a task history of its own"
    else "--project-cache-dir $advancedCache is for Advanced only (-Pdatapavan.edition=advanced)"
}

// One allowlist per edition (ADR 0045, decision 9), checked on the merged manifest, so that no library adds
// a permission, an app query or an open door unnoticed. Fewer is fine; anything else fails the build. Each
// permission maps to the android:maxSdkVersion it must carry, or "" for none.
val basicPermissions = mapOf(
    // Every installed app; an audit with a filtered list would be incomplete by design (ADR 0014).
    "android.permission.QUERY_ALL_PACKAGES" to "",
    // Usage access, special access that the user grants in Settings (ADR 0022).
    "android.permission.PACKAGE_USAGE_STATS" to "",
    // Which networks there are, and whether a VPN is active.
    "android.permission.ACCESS_NETWORK_STATE" to "",
    // Hides other apps' overlays from Datapavan's windows, Android 12 and later (ADR 0040).
    "android.permission.HIDE_OVERLAY_WINDOWS" to "",
    // androidx.core defines it, app-internal, for its non-exported receivers.
    "$editionApplicationId.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" to "",
)
// What Watch adds in Advanced (ADR 0034).
val watchPermissions = mapOf(
    // Sockets, to pass each app's traffic on to where it was going.
    "android.permission.INTERNET" to "",
    // Only Android 10 and 11 need it, to follow the network under the tunnel.
    "android.permission.CHANGE_NETWORK_STATE" to "30",
    "android.permission.POST_NOTIFICATIONS" to "",
    // Android 17: other apps' traffic to the local network leaves through Watch's sockets.
    "android.permission.ACCESS_LOCAL_NETWORK" to "",
)
val allowedPermissions = if (advanced) basicPermissions + watchPermissions else basicPermissions
// What users are taught each edition never holds (ADR 0045, decisions 1, 3 and 4). The build refuses them by
// name as well, so that a wider allowlist cannot quietly break the sentence.
val neverRequested = if (advanced) {
    listOf(
        "CAMERA", "RECORD_AUDIO",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    ).map { "android.permission.$it" }
} else {
    listOf("android.permission.INTERNET")
}
check(neverRequested.none { it in allowedPermissions }) { "The $edition allowlist holds a permission the edition never requests" }
// The permissions the build may define: androidx.core's, signature only.
val allowedPermissionDefinitions = listOf("$editionApplicationId.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
// Exported components, each with the permission that guards it ("" for none): the launcher entry, and
// androidx's profile installer, which only the shell's DUMP may reach. Advanced's debug builds also export
// Watch's screen for the emulator checks (watch/src/debug).
val allowedExported = mapOf(
    "org.visadahyu.datapavan.MainActivity" to "",
    "androidx.profileinstaller.ProfileInstallReceiver" to "android.permission.DUMP",
)
val allowedExportedInDebug = if (advanced) mapOf("org.visadahyu.datapavan.watch.MainActivity" to "") else emptyMap()

// The services that parse untrusted input, which must stay in an isolated process (ADR 0045, decision 9).
val isolatedServices = listOf("org.visadahyu.datapavan.audit.ParserService")

// The native libraries each APK must carry, with the JNI symbol each must export (core/jni and NativeCore.kt;
// core/watch-jni and Engine.kt), and those it must not: Basic never carries Watch's engine.
val requiredLibraries = buildMap {
    put("libdatapavan.so", "Java_org_visadahyu_datapavan_core_NativeCore_version")
    if (advanced) put("libdatapavan_watch.so", "Java_org_visadahyu_datapavan_watch_Engine_nativeStart")
}
val forbiddenLibraries = if (advanced) emptyList() else listOf("libdatapavan_watch.so")
// The methods of WatchVpnService that Watch's library calls back by name (core/watch-jni/src/lib.rs), which
// R8 must neither remove nor rename (watch/proguard-rules.pro).
val jniCallbacks = if (advanced) listOf("ownerUid", "protectSocket", "logRecords") else emptyList()

android {
    namespace = "org.visadahyu.datapavan"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = editionApplicationId
        minSdk = 29
        targetSdk = 37
        // Basic's version, on lines of their own: docs/RELEASE.md and scripts/release-rehearsal.sh read them.
        versionCode = 3
        versionName = "0.1.2"
        // Advanced's first release is 0.2.0, the version Watch had as an app of its own (ADR 0045).
        if (advanced) { versionCode = 1; versionName = "0.2.0" }
        // The release's date, set with the version (docs/RELEASE.md, step 1). The app has no internet
        // access, so this date is all it knows of how old it is (Release.kt).
        buildConfigField("String", "RELEASE_DATE", "\"2026-11-08\"")
        // Lite: Google Play updates it, so it says nothing of newer versions; About names both editions.
        buildConfigField("boolean", "PLAY", lite.toString())
        // Whether Watch is in this build: the audit then opens it from its network page.
        buildConfigField("boolean", "ADVANCED", advanced.toString())
        // Every edition's name carries Datapavan and the edition, in Latin letters in every language,
        // Google Play included, so that no one takes Basic for the full app (ADR 0045, decision 1).
        resValue("string", "app_name", if (advanced) "Datapavan Advanced" else "Datapavan Basic")
        manifestPlaceholders["appIcon"] = if (advanced) "@mipmap/ic_launcher_advanced" else "@mipmap/ic_launcher"
        // The ABIs we ship: arm64 for real phones; 32-bit ARM for the many low-cost phones whose
        // Android is 32-bit although their processor is not; x86_64 for the emulator and ChromeOS.
        // This list is the single source of truth; the Rust build reads it in finalizeDsl.
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
        buildConfig = true
        // app_name differs by edition (above).
        resValues = true
        // The interface to the parsers' isolated process (src/main/aidl, audit/ParserService.kt).
        aidl = true
    }

    androidResources {
        // Advanced: Watch's table from address to organisation (ADR 0036) is read in place, which needs
        // it stored.
        if (advanced) noCompress += "bin"
        generateLocaleConfig = true
        // Ship only the languages we translate. Without this, library translations for ~85
        // languages are bundled and the UI would mix languages on unsupported locales.
        localeFilters += listOf("en", "fr", "de", "fa", "ru", "zh-rCN", "es", "ar")
    }

    // The language can be chosen in the app (ADR 0027), so every install carries all of them, also
    // from an app bundle.
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
    implementation(project(":shared"))
    if (advanced) implementation(project(":watch"))
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
            // Datasets that only Watch uses go into Watch's APK, not the audit app's (ADR 0036): the
            // organisation table, and the resolvers compiled into Watch's engine.
            .filter { it.relativeTo(source).invariantSeparatorsPath.substringBefore('/') !in setOf("dbip-asn", "resolvers") }
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
 * Verifies the merged manifest against the edition's allowlist and passes it on unchanged. Wired as a
 * transform of MERGED_MANIFEST, so every consumer (APK, bundle, install) depends on it and cannot bypass
 * it. It checks <uses-permission> and <uses-permission-sdk-23> (with their maxSdkVersion), the permissions
 * the edition never requests, <permission> definitions (signature only), <queries> (the one launcher
 * intent, nothing else), every exported component with the permission that guards it, and that no
 * package shares this one's UID.
 */
abstract class ManifestAllowlistCheck : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val edition: Property<String>

    @get:Input
    abstract val permissions: MapProperty<String, String>

    @get:Input
    abstract val never: ListProperty<String>

    @get:Input
    abstract val definitions: ListProperty<String>

    @get:Input
    abstract val exported: MapProperty<String, String>

    /** Services that must run isolated and unexported: the parsers of untrusted input. */
    @get:Input
    abstract val isolated: ListProperty<String>

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
        // Packages that share a UID share their permissions: a shared UID with an app that holds INTERNET
        // would give it to this one, whatever this manifest requests (ADR 0045, decision 9).
        if (document.documentElement.getAttributeNS(androidNs, "sharedUserId").isNotEmpty()) {
            problems += "shares a UID with other packages (android:sharedUserId)"
        }
        for (element in elements("uses-permission") + elements("uses-permission-sdk-23")) {
            val name = element.android("name")
            val maxSdk = element.android("maxSdkVersion")
            when {
                name in never.get() -> problems += "requests $name, which this edition never requests"
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
        for (name in isolated.get()) {
            val service = elements("service").firstOrNull { it.android("name") == name }
            if (service == null || service.android("isolatedProcess") != "true" || service.android("exported") != "false") {
                problems += "does not run $name isolated and unexported"
            }
        }
        if (problems.isNotEmpty()) {
            throw GradleException("The ${edition.get()} edition's merged manifest holds what its allowlist does not allow (ADR 0045):\n  " + problems.joinToString("\n  "))
        }
        source.copyTo(checkedManifest.get().asFile, overwrite = true)
    }
}

/**
 * Fails if a built APK lacks a native library the edition needs for a shipped ABI, if a library does not
 * export its JNI symbol, if it carries one the edition must not (Basic never carries Watch's engine), or if
 * the APK's code lacks a method a library calls back by name: R8 would have removed or renamed it, and the
 * engine would fail at run time without a word.
 */
abstract class ApkNativeLibraryCheck : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:Internal
    abstract val loader: Property<BuiltArtifactsLoader>

    @get:Input
    abstract val abis: ListProperty<String>

    /** Each library the APK must carry, with the JNI symbol it must export. */
    @get:Input
    abstract val libraries: MapProperty<String, String>

    @get:Input
    abstract val forbidden: ListProperty<String>

    @get:Input
    abstract val callbacks: ListProperty<String>

    @get:OutputFile
    abstract val report: RegularFileProperty

    @TaskAction
    fun verify() {
        val artifacts = loader.get().load(apkDirectory.get())
            ?: throw GradleException("No APK found in ${apkDirectory.get().asFile}")
        val lines = mutableListOf<String>()
        artifacts.elements.forEach { element ->
            val apk = File(element.outputFile).name
            ZipFile(element.outputFile).use { zip ->
                abis.get().forEach { abi ->
                    libraries.get().forEach { (library, symbol) ->
                        val entry = zip.getEntry("lib/$abi/$library")
                            ?: throw GradleException("${element.outputFile}: lib/$abi/$library is missing")
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        if (!String(bytes, Charsets.ISO_8859_1).contains(symbol)) {
                            throw GradleException("${element.outputFile}: lib/$abi/$library does not export $symbol")
                        }
                        lines += "OK $apk lib/$abi/$library (${bytes.size} bytes)"
                    }
                }
                forbidden.get().forEach { library ->
                    zip.entries().asSequence().firstOrNull { it.name.endsWith("/$library") }?.let {
                        throw GradleException("${element.outputFile}: ${it.name} is in an edition that must not carry it")
                    }
                    lines += "OK $apk has no $library"
                }
                // A method name the code keeps is in some dex file's string table.
                val code = zip.entries().asSequence().filter { it.name.matches(Regex("classes\\d*\\.dex")) }
                    .joinToString("") { entry -> String(zip.getInputStream(entry).use { it.readBytes() }, Charsets.ISO_8859_1) }
                callbacks.get().forEach { name ->
                    if (!code.contains(name)) {
                        throw GradleException("${element.outputFile}: no method $name in its code; Watch's library calls it by name (watch/proguard-rules.pro)")
                    }
                    lines += "OK $apk keeps $name"
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

        val manifestCheck = tasks.register<ManifestAllowlistCheck>("checkManifest$suffix") {
            edition.set(editionName)
            permissions.set(allowedPermissions)
            never.set(neverRequested)
            definitions.set(allowedPermissionDefinitions)
            exported.set(if (variant.buildType == "debug") allowedExported + allowedExportedInDebug else allowedExported)
            isolated.set(isolatedServices)
        }
        variant.artifacts.use(manifestCheck)
            .wiredWithFiles(ManifestAllowlistCheck::mergedManifest, ManifestAllowlistCheck::checkedManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)

        tasks.register<ApkNativeLibraryCheck>("verifyApk$suffix") {
            apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
            loader.set(variant.artifacts.getBuiltArtifactsLoader())
            abis.set(shippedAbis)
            libraries.set(requiredLibraries)
            forbidden.set(forbiddenLibraries)
            callbacks.set(jniCallbacks)
            report.set(layout.buildDirectory.file("reports/apk-native/${variant.name}.txt"))
        }
    }
}
