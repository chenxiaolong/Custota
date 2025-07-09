/*
 * SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import com.chiller3.custota.settings.SettingsActivity

class Notifications(
    private val context: Context,
) {
    companion object {
        const val CHANNEL_ID_PERSISTENT = "persistent"
        const val CHANNEL_ID_CHECK = "check"
        const val CHANNEL_ID_FAILURE = "failure"
        const val CHANNEL_ID_SUCCESS = "success"

        private val LEGACY_CHANNEL_IDS = arrayOf<String>()

        const val ID_PERSISTENT = 1
        const val ID_ALERT = 2
    }

    private val notificationManager = context.getSystemService(NotificationManager::class.java)

    private fun createPersistentChannel() = NotificationChannel(
        CHANNEL_ID_PERSISTENT,
        context.getString(R.string.notification_channel_persistent_name),
        NotificationManager.IMPORTANCE_LOW,
    ).apply {
        description = context.getString(R.string.notification_channel_persistent_desc)
    }

    private fun createCheckAlertsChannel() = NotificationChannel(
        CHANNEL_ID_CHECK,
        context.getString(R.string.notification_channel_check_name),
        NotificationManager.IMPORTANCE_HIGH,
    ).apply {
        description = context.getString(R.string.notification_channel_check_desc)
    }

    private fun createFailureAlertsChannel() = NotificationChannel(
        CHANNEL_ID_FAILURE,
        context.getString(R.string.notification_channel_failure_name),
        NotificationManager.IMPORTANCE_HIGH,
    ).apply {
        description = context.getString(R.string.notification_channel_failure_desc)
    }

    private fun createSuccessAlertsChannel() = NotificationChannel(
        CHANNEL_ID_SUCCESS,
        context.getString(R.string.notification_channel_success_name),
        NotificationManager.IMPORTANCE_HIGH,
    ).apply {
        description = context.getString(R.string.notification_channel_success_desc)
    }

    /**
     * Ensure notification channels are up-to-date.
     *
     * Legacy notification channels are deleted without migrating settings.
     */
    fun updateChannels() {
        notificationManager.createNotificationChannels(listOf(
            createPersistentChannel(),
            createCheckAlertsChannel(),
            createFailureAlertsChannel(),
            createSuccessAlertsChannel(),
        ))
        LEGACY_CHANNEL_IDS.forEach { notificationManager.deleteNotificationChannel(it) }
    }

    /** Create a persistent notification for background services. */
    fun createPersistentNotification(
        @StringRes titleResId: Int,
        message: String?,
        @DrawableRes iconResId: Int,
        actions: List<Pair<Int, Intent>>,
        progressCurrent: Int?,
        progressMax: Int?,
        showImmediately: Boolean,
    ): Notification {
        require((progressCurrent == null) == (progressMax == null)) {
            "Must specify both current and max progress or neither"
        }

        val notificationIntent = Intent(context, SettingsActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(context, CHANNEL_ID_PERSISTENT).run {
            setContentTitle(context.getText(titleResId))
            if (message != null) {
                setContentText(message)
                style = Notification.BigTextStyle()
            }
            setSmallIcon(iconResId)
            setContentIntent(pendingIntent)
            setOngoing(true)
            setOnlyAlertOnce(true)

            if (progressCurrent != null && progressMax != null) {
                // We also show an indeterminate progress bar when the current progress is 0 because
                // some phases, like the finalization and cleanup phases, don't always report their
                // actual progress.
                if (progressMax <= 0 || progressCurrent == 0) {
                    setProgress(0, 0, true)
                } else {
                    setProgress(progressMax, progressCurrent, false)
                }
            }

            for ((actionTextResId, actionIntent) in actions) {
                val actionPendingIntent = PendingIntent.getService(
                    context,
                    0,
                    actionIntent,
                    PendingIntent.FLAG_IMMUTABLE or
                            PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_ONE_SHOT,
                )

                addAction(Notification.Action.Builder(
                    null,
                    context.getString(actionTextResId),
                    actionPendingIntent,
                ).build())
            }

            // Inhibit 10-second delay when showing persistent notification
            if (showImmediately) {
                setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            }

            build()
        }
    }

    /**
     * Send an alert notification with the given [title] and [icon].
     *
     * * If [errorMsg] is not null, then it is appended to the text with a black line before it.
     */
    fun sendAlertNotification(
        channel: String,
        onlyAlertOnce: Boolean,
        @StringRes title: Int,
        @DrawableRes icon: Int,
        errorMsg: String?,
        actions: List<Pair<Int, Intent>>,
        showOnLockScreen: Boolean,
    ) {
        val notification = Notification.Builder(context, channel).run {
            val text = buildString {
                val errorMsgTrimmed = errorMsg?.trim()
                if (!errorMsgTrimmed.isNullOrBlank()) {
                    append(errorMsgTrimmed)
                }
            }

            setContentTitle(context.getString(title))
            if (text.isNotBlank()) {
                setContentText(text)
                style = Notification.BigTextStyle()
            }
            setSmallIcon(icon)
            setOnlyAlertOnce(onlyAlertOnce)
            if (showOnLockScreen) {
                setVisibility(Notification.VISIBILITY_PUBLIC)
            }

            for ((actionTextResId, actionIntent) in actions) {
                val actionPendingIntent = PendingIntent.getService(
                    context,
                    0,
                    actionIntent,
                    PendingIntent.FLAG_IMMUTABLE or
                            PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_ONE_SHOT,
                )

                addAction(Notification.Action.Builder(
                    null,
                    context.getString(actionTextResId),
                    actionPendingIntent,
                ).build())
            }

            build()
        }

        notificationManager.notify(ID_ALERT, notification)
    }

    fun dismissAlert() {
        notificationManager.cancel(ID_ALERT)
    }
}
