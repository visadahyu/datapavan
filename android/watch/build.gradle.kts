import com.android.build.api.artifact.SingleArtifact
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

    defaultConfig {
        applicationId = watchApplicationId
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.2.0"
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

androidComponents {
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar(Char::uppercase)
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
