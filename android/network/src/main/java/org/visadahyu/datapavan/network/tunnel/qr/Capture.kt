package org.visadahyu.datapavan.network.tunnel.qr

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import androidx.core.content.FileProvider
import java.io.File
import java.security.SecureRandom

/**
 * A photo of a WireGuard configuration's QR code, taken by the phone's own camera app for Watch (W7, part 2; ADR
 * 0035, question 10): Watch never holds `CAMERA`. The camera writes the photo to a file of Watch's own, in its
 * cache, through a URI of Watch's FileProvider granted for writing to that one file, and revoked once the camera
 * answers. The photo holds the configuration's private key, so the file is deleted right after it is read, when
 * reading fails, when the camera is cancelled, and, for one a crash left, at Watch's next start ([deleteLeftovers]).
 * Since Android 11 only a preinstalled camera answers `ACTION_IMAGE_CAPTURE`; on Android 10 the intent names the
 * preinstalled camera itself, so that on every version only the phone's own camera sees the picture.
 */
object Capture {
    private const val FOLDER = "qr-capture"

    /** The FileProvider's authority (the watch module's manifest). */
    fun authority(context: Context) = "${context.packageName}.watch.capture"

    /** A new, empty file for one photo, its name drawn at random. */
    fun newFile(context: Context): File {
        val folder = File(context.cacheDir, FOLDER).apply { mkdirs() }
        val name = ByteArray(12).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        return File(folder, "$name.jpg").apply { createNewFile() }
    }

    fun uri(context: Context, file: File): Uri = FileProvider.getUriForFile(context, authority(context), file)

    /**
     * The camera's intent for [uri], granted for writing to it alone, or null when the phone has no preinstalled
     * camera that answers it.
     */
    fun intent(context: Context, uri: Uri): Intent? {
        val intent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
            .putExtra(MediaStore.EXTRA_OUTPUT, uri)
            .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        // The grant goes with the intent's ClipData; EXTRA_OUTPUT alone carries none.
        intent.clipData = ClipData.newRawUri("", uri)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            val camera = preinstalledCamera(context.packageManager, intent) ?: return null
            intent.setPackage(camera)
        }
        return intent
    }

    /** Android 10: the package of a preinstalled app that answers [intent], the phone's own camera. */
    private fun preinstalledCamera(packages: PackageManager, intent: Intent): String? {
        @Suppress("DEPRECATION")
        val answering = packages.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        return answering.map { it.activityInfo.applicationInfo }
            .firstOrNull { it.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 }
            ?.packageName
    }

    /** Takes the grant back, whatever the camera did. */
    fun revoke(context: Context, uri: Uri) {
        context.revokeUriPermission(uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    /**
     * What the camera's answer gives: the photo [file] read by [read] when the camera took it ([taken]), else nothing; the
     * file is deleted on every path, a read that fails or throws included.
     */
    fun <T> finish(file: File, taken: Boolean, read: (File) -> T): T? = try {
        if (taken && file.length() > 0) read(file) else null
    } finally {
        file.delete()
    }

    /**
     * A photo whose camera never answered, as when Watch's screen finishes while the camera has it (its task removed
     * from Recents) and Watch's process lives on (fix round, security review m7): the write grant is taken back by
     * [revoke], so that the camera cannot write the file again, and the file is deleted, whatever the revoke does.
     */
    fun abandon(file: File, revoke: () -> Unit) {
        try {
            revoke()
        } finally {
            file.delete()
        }
    }

    /** Deletes every photo left but [keep], which a camera may still be writing for a screen that comes back. */
    fun deleteLeftovers(context: Context, keep: String? = null) = deleteLeftovers(File(context.cacheDir, FOLDER), keep)

    /** Deletes every file in [folder] but [keep]. */
    fun deleteLeftovers(folder: File, keep: String?) {
        folder.listFiles()?.forEach { if (it.name != keep) it.delete() }
    }
}
