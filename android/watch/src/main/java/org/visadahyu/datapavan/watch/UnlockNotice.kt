package org.visadahyu.datapavan.watch

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/**
 * The one notification Watch shows while configurations wrapped under key B wait for the phone's unlock (the
 * maintainer's decision of 2026-11-20, ADR 0035): with ADR 0047's profile on, Watch started again while the phone is
 * locked cannot open them, and their apps wait, sending nothing, until the unlock. It says so in plain words, and
 * names no provider and no configuration, on the lock screen or off it. It goes once the configurations are set
 * after the unlock. From Android 13 it shows only once the user allows Watch's notifications, which W9's onboarding
 * asks with the profile's switch.
 */
internal object UnlockNotice {
    private const val CHANNEL = "watch-unlock"
    private const val ID = 7_201

    /** Shows the notification while [waiting], and takes it away otherwise. */
    fun show(context: Context, waiting: Boolean) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (!waiting) {
            manager.cancel(ID)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, context.getString(R.string.unlock_channel), NotificationManager.IMPORTANCE_DEFAULT),
        )
        val title = context.getString(R.string.unlock_title)
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        // The lock screen's version: the title alone.
        val locked = Notification.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .build()
        val notice = Notification.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(context.getString(R.string.unlock_text))
            .setStyle(Notification.BigTextStyle().bigText(context.getString(R.string.unlock_text)))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(locked)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .build()
        manager.notify(ID, notice)
    }

    /** Whether it shows now, for the debug builds' dump. */
    fun shown(context: Context): Boolean =
        context.getSystemService(NotificationManager::class.java)?.activeNotifications?.any { it.id == ID } == true
}
