// Datapavan Watch's spike: a VpnService that runs one of three packet engines (../README.md).
plugins {
    id("com.android.application")
}

android {
    namespace = "org.visadahyu.datapavan.watch.spike"
    compileSdk = 37
    ndkVersion = "30.0.16248370"
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    defaultConfig {
        applicationId = "org.visadahyu.datapavan.watch.spike"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "spike"
    }
    // Native libraries come from cargo-ndk (libspike_engine.so) and gomobile (the gVisor AAR).
    sourceSets["main"].jniLibs.directories.add("build/rustJniLibs")
}

dependencies {
    // Added when the Go engine is built: implementation(files("libs/gvisorengine.aar"))
}
