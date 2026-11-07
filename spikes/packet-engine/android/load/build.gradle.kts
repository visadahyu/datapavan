// The workload whose traffic the spike's tunnel carries: downloads, uploads and request latency.
plugins {
    id("com.android.application")
}

android {
    namespace = "org.visadahyu.datapavan.watch.load"
    compileSdk = 37
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    defaultConfig {
        applicationId = "org.visadahyu.datapavan.watch.load"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "spike"
    }
}
