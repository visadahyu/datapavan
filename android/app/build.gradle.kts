import com.android.build.api.artifact.SingleArtifact
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Permissions that must never appear in the merged manifest. v0.1 is network-free by design;
// if any library tries to add one of these, the build fails instead of silently shipping it.
val forbiddenPermissions = listOf("android.permission.INTERNET")

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
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    testImplementation(libs.junit)
}

/** Builds the Rust JNI library for every shipped ABI with cargo-ndk. */
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

    @get:Internal
    abstract val ndkDir: DirectoryProperty

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
        execOperations.exec {
            workingDir = workspaceDir.get().asFile
            environment("ANDROID_NDK_HOME", ndkDir.get().asFile.absolutePath)
            commandLine(args)
        }
    }
}

/** Fails the build if the merged manifest requests a forbidden permission. */
abstract class ForbiddenPermissionsCheck : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val manifest: RegularFileProperty

    @get:Input
    abstract val forbidden: ListProperty<String>

    @get:OutputFile
    abstract val report: RegularFileProperty

    @TaskAction
    fun verify() {
        val text = manifest.get().asFile.readText()
        val found = forbidden.get().filter { permission ->
            Regex("""<uses-permission[^>]*android:name="${Regex.escape(permission)}"""").containsMatchIn(text)
        }
        if (found.isNotEmpty()) {
            throw GradleException("Forbidden permission(s) in the merged manifest: $found")
        }
        report.get().asFile.writeText("OK: none of $forbidden is requested.\n")
    }
}

val rustWorkspace = rootProject.layout.projectDirectory.dir("../core")
val cargoExecutable = providers.environmentVariable("CARGO")
    .orElse(providers.systemProperty("user.home").map { "$it/.cargo/bin/cargo" })

var shippedAbis: List<String> = emptyList()

androidComponents {
    finalizeDsl { extension ->
        shippedAbis = extension.defaultConfig.ndk.abiFilters.sorted()
    }

    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar(Char::uppercase)

        val cargoTask = tasks.register<CargoNdkTask>("cargoNdk$suffix") {
            sources.from(fileTree(rustWorkspace) { exclude("target/**") })
            sources.from(rootProject.layout.projectDirectory.file("../rust-toolchain.toml"))
            workspaceDir.set(rustWorkspace)
            abis.set(shippedAbis)
            platformLevel.set(variant.minSdk.apiLevel)
            release.set(variant.buildType == "release")
            cargo.set(cargoExecutable)
            ndkDir.set(androidComponents.sdkComponents.ndkDirectory)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoTask, CargoNdkTask::outputDir)

        val permissionCheck = tasks.register<ForbiddenPermissionsCheck>("checkPermissions$suffix") {
            manifest.set(variant.artifacts.get(SingleArtifact.MERGED_MANIFEST))
            forbidden.set(forbiddenPermissions)
            report.set(layout.buildDirectory.file("reports/permissions/${variant.name}.txt"))
        }
        tasks.matching { it.name == "assemble$suffix" || it.name == "check" }
            .configureEach { dependsOn(permissionCheck) }
    }
}
