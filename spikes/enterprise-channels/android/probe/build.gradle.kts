// See ../../README.md.
plugins {
    id("com.android.application")
}

android {
    namespace = "org.visadahyu.datapavan.enterprise.probe"
    compileSdk = 37
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    defaultConfig {
        applicationId = "org.visadahyu.datapavan.enterprise.probe"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "spike"
    }
}

dependencies {
    implementation("androidx.enterprise:enterprise-feedback:1.1.0")
}
