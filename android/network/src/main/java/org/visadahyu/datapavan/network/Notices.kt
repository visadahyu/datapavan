package org.visadahyu.datapavan.network

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
 * The network part's two notifications about its WireGuard configurations (W7, part 2, fix round; the maintainer's
 * decisions of 2026-11-20, ADR 0035). Each names no provider and no configuration, on the lock screen or off it, whose
 * version is its title alone; each opens the network screen. From Android 13 they show only once the user allows
 * the network part's notifications, which W9's onboarding asks.
 */
internal object Notices {
    /** What a notification is for. */
    enum class Kind(val id: Int, val title: Int, val text: Int) {
        /**
         * Configurations under key B wait for the phone's unlock: with ADR 0047's profile on, the network part started
         * again while the phone is locked cannot open them, and their apps wait until the unlock, when it goes.
         */
        UNLOCK(7_201, R.string.unlock_title, R.string.unlock_text),

        /**
         * What the network part kept of its configurations can no longer be opened (key A gone for good): every app is
         * held until the user chooses on the network screen, when it goes.
         */
        LOST(7_202, R.string.lost_title, R.string.lost_text),

        /**
         * Direct apps' names go to the network's resolver, since no encrypted way answers (W8, part 1): only when
         * the user turned it on, since the network part has no tile until W9; it goes as soon as an encrypted way
         * answers.
         */
        DNS_FALLBACK(7_203, R.string.dns_fallback_title, R.string.dns_fallback_text),
    }

    private const val CHANNEL = "network-unlock"

    /** The fallback's own channel, so that the user can silence it apart from the others. */
    private const val DNS_CHANNEL = "network-dns"

    /** Shows the notification [kind] while [on], and takes it away otherwise. */
    fun show(context: Context, kind: Kind, on: Boolean) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (!on) {
            manager.cancel(kind.id)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val channel = if (kind == Kind.DNS_FALLBACK) DNS_CHANNEL else CHANNEL
        manager.createNotificationChannel(
            if (kind == Kind.DNS_FALLBACK) {
                NotificationChannel(DNS_CHANNEL, context.getString(R.string.dns_fallback_channel), NotificationManager.IMPORTANCE_LOW)
            } else {
                NotificationChannel(CHANNEL, context.getString(R.string.unlock_channel), NotificationManager.IMPORTANCE_DEFAULT)
            },
        )
        val title = context.getString(kind.title)
        val text = context.getString(kind.text)
        val open = PendingIntent.getActivity(
            context,
            kind.id,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        // The lock screen's version: the title alone.
        val locked = Notification.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .build()
        val notice = Notification.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(locked)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .build()
        manager.notify(kind.id, notice)
    }

    /** Whether [kind] shows now, for the debug builds' dump. */
    fun shown(context: Context, kind: Kind): Boolean =
        context.getSystemService(NotificationManager::class.java)?.activeNotifications?.any { it.id == kind.id } == true
}
