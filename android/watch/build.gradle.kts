import com.android.build.api.artifact.SingleArtifact
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Datapavan Watch (ADR 0029): the VPN, built from the same repository as the audit app and signed with
// the same key. Its permissions are exactly those ADR 0034 allows; the build fails if the merged
// manifest asks for any other, so that no library adds one unnoticed. The AndroidX permission is
// app-internal: androidx.core defines it with protectionLevel="signature" for non-exported receivers.
val allowedPermissions = listOf(
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "org.visadahyu.datapavan.watch.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
)

android {
    namespace = "org.visadahyu.datapavan.watch"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.visadahyu.datapavan.watch"
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
 * Verifies the merged manifest against the allowed permissions and passes it on unchanged. Wired as a
 * transform of MERGED_MANIFEST, so every consumer (APK, bundle, install) depends on it and cannot
 * bypass it. Both <uses-permission> and <uses-permission-sdk-23> count.
 */
abstract class AllowedPermissionsCheck : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val allowed: ListProperty<String>

    @get:OutputFile
    abstract val checkedManifest: RegularFileProperty

    @TaskAction
    fun verify() {
        val source = mergedManifest.get().asFile
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(source)
        val requested = listOf("uses-permission", "uses-permission-sdk-23").flatMap { tag ->
            val nodes = document.getElementsByTagName(tag)
            (0 until nodes.length).map { index ->
                nodes.item(index).attributes.getNamedItemNS("http://schemas.android.com/apk/res/android", "name").nodeValue
            }
        }
        val extra = requested.filter { it !in allowed.get() }
        if (extra.isNotEmpty()) {
            throw GradleException("Permission(s) in Watch's merged manifest that ADR 0034 does not allow: $extra")
        }
        source.copyTo(checkedManifest.get().asFile, overwrite = true)
    }
}

androidComponents {
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar(Char::uppercase)
        val permissionCheck = tasks.register<AllowedPermissionsCheck>("checkPermissions$suffix") {
            allowed.set(allowedPermissions)
        }
        variant.artifacts.use(permissionCheck)
            .wiredWithFiles(AllowedPermissionsCheck::mergedManifest, AllowedPermissionsCheck::checkedManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)
    }
}
