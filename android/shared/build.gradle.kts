plugins {
    alias(libs.plugins.android.library)
}

// Code every edition shares (ADR 0045, decision 10): the rules that judge a copy's signing key (ADR 0018)
// and the protection of every screen (ADR 0040). A library rather than a source directory added to each
// module, since Advanced includes Watch's module and would otherwise compile the same classes twice.
android {
    namespace = "org.visadahyu.datapavan.shared"
    compileSdk = 37

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        // These checks need network access and only say "a newer version exists".
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
    }
}

dependencies {
    // The same versions as the application's, through Compose's bill of materials.
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
}
