# The default optimize rules keep the classes with native methods and those methods' names: the calls
# from Kotlin into the Rust library (Engine.kt). They do not keep the methods the Rust library calls
# back by name through JNI (core/watch-jni/src/lib.rs). Until 2026-11-10 R8 renamed them in the release
# build, so its engine could neither protect its sockets, nor name a flow's app, nor write the log.
# verifyApkRelease (build.gradle.kts) fails if any of them is missing from the APK's code.
-keepclassmembers class org.visadahyu.datapavan.watch.WatchVpnService {
    public int ownerUid(int, byte[], int, byte[], int);
    public boolean protectSocket(int);
    public void logRecords(byte[]);
}
