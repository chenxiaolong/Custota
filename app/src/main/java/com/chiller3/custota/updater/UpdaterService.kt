/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcelable
import android.os.PowerManager
import android.util.Log
import androidx.annotation.UiThread
import androidx.core.content.IntentCompat
import com.chiller3.custota.Notifications
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.extension.toSingleLineString

class UpdaterService : Service(), UpdaterThread.UpdaterThreadListener {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var prefs: Preferences
    private lateinit var notificationManager: NotificationManager
    private lateinit var notifications: Notifications

    private var updaterThread: UpdaterThread? = null
    private var updaterAction: UpdaterThread.Action? = null
    private var silenceForPeriodic = false
    private var progressState: ProgressState? = null

    override fun onCreate() {
        super.onCreate()

        prefs = Preferences(this)
        notificationManager = getSystemService(NotificationManager::class.java)
        notifications = Notifications(this)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "Received intent: $intent")

        try {
            when (val action = intent?.action) {
                ACTION_START -> {
                    // We're launched by startForegroundService(). Android requires the foreground
                    // notification to be shown, even if stopService() is called before this method
                    // returns.
                    updateForegroundNotification(false)

                    if (prefs.otaServerUrl != null) {
                        startUpdate(intent)
                    } else {
                        Log.w(TAG, "Not starting thread because no URL is configured")
                    }
                }
                ACTION_PAUSE, ACTION_RESUME -> {
                    updaterThread?.isPaused = action == ACTION_PAUSE
                    updateForegroundNotification(true)
                }
                ACTION_CANCEL -> {
                    updaterThread?.cancel()
                }
                ACTION_REBOOT -> {
                    getSystemService(PowerManager::class.java).reboot(null)
                }
                ACTION_SCHEDULE -> {
                    UpdaterJob.scheduleImmediate(this, IntentCompat.getParcelableExtra(
                        intent, EXTRA_ACTION, UpdaterThread.Action::class.java)!!)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to handle intent: $intent", e)
            notifyAlert(UpdaterThread.UpdateFailed(e.toSingleLineString()))
        }

        tryStop()
        return START_NOT_STICKY
    }

    private fun startUpdate(intent: Intent) {
        if (updaterThread == null) {
            Log.d(TAG, "Creating new updater thread")

            // IntentCompat is required due to an Android 13 bug that's only fixed in 14+
            // https://issuetracker.google.com/issues/274185314
            val network = IntentCompat.getParcelableExtra(
                intent, EXTRA_NETWORK, Network::class.java)!!
            val action = IntentCompat.getParcelableExtra(
                intent, EXTRA_ACTION, UpdaterThread.Action::class.java)!!
            val silent = intent.getBooleanExtra(EXTRA_SILENT, false)

            // Clear all stale alert notifications when initiated by the user. For the periodic job,
            // we want to leave the existing notification visible so that it can be updated with the
            // new status without re-alerting the user when onlySendOnce is true.
            if (!silent) {
                notifications.dismissAlert()
            }

            updateForegroundNotification(true)

            updaterThread = UpdaterThread(this, network, action, this).apply {
                start()
            }

            updaterAction = action
            silenceForPeriodic = silent

            Log.d(TAG, "More silent behavior for periodic job: $silenceForPeriodic")
        }
    }

    private fun tryStop() {
        Log.d(TAG, "Trying to stop service if possible")

        if (updaterThread == null) {
            Log.d(TAG, "Updater thread completed; stopping service")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    @UiThread
    private fun threadExited() {
        updaterThread = null
        updaterAction = null
        silenceForPeriodic = false
        progressState = null
        tryStop()
    }

    private fun createActionIntent(action: String): Intent =
        Intent(this, this::class.java).apply {
            this.action = action
        }

    @UiThread
    private fun updateForegroundNotification(showImmediately: Boolean) {
        val state = progressState
        Log.d(TAG, "Updating foreground notification for state: $state")

        val titleResId = when (state?.type) {
            UpdaterThread.ProgressType.INIT, null -> R.string.notification_state_init
            UpdaterThread.ProgressType.CHECK -> R.string.notification_state_check
            UpdaterThread.ProgressType.UPDATE -> R.string.notification_state_install
            UpdaterThread.ProgressType.VERIFY -> R.string.notification_state_verify
            UpdaterThread.ProgressType.FINALIZE -> R.string.notification_state_finalize
        }
        val actionResIds = mutableListOf<Int>()
        val actionIntents = mutableListOf<Intent>()

        updaterThread?.let { thread ->
            if (thread.isPaused) {
                actionResIds.add(R.string.notification_action_resume)
                actionIntents.add(createActionIntent(ACTION_RESUME))
            } else {
                actionResIds.add(R.string.notification_action_pause)
                actionIntents.add(createActionIntent(ACTION_PAUSE))
            }
            actionResIds.add(R.string.notification_action_cancel)
            actionIntents.add(createActionIntent(ACTION_CANCEL))
        }

        val notification = notifications.createPersistentNotification(
            titleResId,
            null,
            R.drawable.ic_notifications,
            actionResIds.zip(actionIntents),
            state?.current,
            state?.max,
            showImmediately,
        )

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
        } else {
            0
        }
        startForeground(Notifications.ID_PERSISTENT, notification, type)
    }

    @UiThread
    private fun notifyAlert(result: UpdaterThread.Result) {
        val channel: String
        val onlyAlertOnce: Boolean
        val titleResId: Int
        val message: String?
        val showInstall: Boolean
        val showRetry: Boolean
        val showReboot: Boolean

        when (result) {
            is UpdaterThread.UpdateAvailable -> {
                channel = Notifications.CHANNEL_ID_CHECK
                // Only bug the user once while the notification is still shown
                onlyAlertOnce = true
                titleResId = R.string.notification_update_available
                message = result.fingerprint
                showInstall = true
                showRetry = false
                showReboot = false
            }
            UpdaterThread.UpdateUnnecessary -> {
                if (silenceForPeriodic) {
                    // No need to harass the user with "OS is already up to date" notifications when
                    // running from the periodic job.
                    return
                }

                channel = Notifications.CHANNEL_ID_CHECK
                onlyAlertOnce = false
                titleResId = R.string.notification_update_unnecessary
                message = null
                showInstall = false
                showRetry = false
                showReboot = false
            }
            UpdaterThread.UpdateSucceeded, UpdaterThread.UpdateNeedReboot -> {
                channel = Notifications.CHANNEL_ID_SUCCESS
                // Only bug the user once while the notification is still shown
                onlyAlertOnce = result is UpdaterThread.UpdateNeedReboot
                titleResId = R.string.notification_update_succeeded
                message = null
                showInstall = false
                showRetry = false
                showReboot = true
            }
            UpdaterThread.UpdateReverted -> {
                channel = Notifications.CHANNEL_ID_SUCCESS
                onlyAlertOnce = false
                titleResId = R.string.notification_update_reverted
                message = null
                showInstall = false
                showRetry = false
                showReboot = false
            }
            UpdaterThread.UpdateCancelled -> {
                channel = Notifications.CHANNEL_ID_FAILURE
                onlyAlertOnce = false
                titleResId = R.string.notification_update_cancelled
                message = null
                showInstall = false
                showRetry = true
                showReboot = false
            }
            is UpdaterThread.UpdateFailed -> {
                channel = Notifications.CHANNEL_ID_FAILURE
                onlyAlertOnce = false
                titleResId = R.string.notification_update_failed
                message = result.errorMsg
                showInstall = false
                showRetry = true
                showReboot = false
            }
        }

        val actionResIds = mutableListOf<Int>()
        val actionIntents = mutableListOf<Intent>()

        if (showInstall) {
            actionResIds.add(R.string.notification_action_install)
            actionIntents.add(createScheduleIntent(this, UpdaterThread.Action.INSTALL))
        }
        if (showRetry) {
            actionResIds.add(R.string.notification_action_retry)
            // Go through job scheduler because we might need a new network
            updaterAction?.let { action ->
                actionIntents.add(createScheduleIntent(this, action))
            }
        }
        if (showReboot) {
            actionResIds.add(R.string.notification_action_reboot)
            actionIntents.add(createActionIntent(ACTION_REBOOT))
        }

        notifications.sendAlertNotification(
            channel,
            onlyAlertOnce,
            titleResId,
            R.drawable.ic_notifications,
            message,
            actionResIds.zip(actionIntents),
        )
    }

    override fun onUpdateResult(thread: UpdaterThread, result: UpdaterThread.Result) {
        handler.post {
            require(thread === updaterThread) { "Bad thread ($thread != $updaterThread)" }
            notifyAlert(result)
            threadExited()
        }
    }

    override fun onUpdateProgress(
        thread: UpdaterThread,
        type: UpdaterThread.ProgressType,
        current: Int,
        max: Int
    ) {
        handler.post {
            require(thread === updaterThread) { "Bad thread ($thread != $updaterThread)" }
            progressState = ProgressState(type, current, max)
            updateForegroundNotification(true)
        }
    }

    private data class ProgressState(
        val type: UpdaterThread.ProgressType,
        val current: Int,
        val max: Int,
    )

    companion object {
        private val TAG = UpdaterService::class.java.simpleName

        private val ACTION_START = "${UpdaterService::class.java.canonicalName}.start"
        private val ACTION_PAUSE = "${UpdaterService::class.java.canonicalName}.pause"
        private val ACTION_RESUME = "${UpdaterService::class.java.canonicalName}.resume"
        private val ACTION_CANCEL = "${UpdaterService::class.java.canonicalName}.cancel"
        private val ACTION_REBOOT = "${UpdaterService::class.java.canonicalName}.reboot"
        private val ACTION_SCHEDULE = "${UpdaterService::class.java.canonicalName}.schedule"

        private const val EXTRA_NETWORK = "network"
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_SILENT = "silent"

        fun createStartIntent(
            context: Context,
            network: Network,
            action: UpdaterThread.Action,
            silent: Boolean,
        ) = Intent(context, UpdaterService::class.java).apply {
            this.action = ACTION_START

            putExtra(EXTRA_NETWORK, network)

            val parcelableAction: Parcelable = action
            putExtra(EXTRA_ACTION, parcelableAction)
            putExtra(EXTRA_SILENT, silent)
        }

        private fun createScheduleIntent(
            context: Context,
            action: UpdaterThread.Action,
        ) = Intent(context, UpdaterService::class.java).apply {
            this.action = ACTION_SCHEDULE

            val parcelableAction: Parcelable = action
            putExtra(EXTRA_ACTION, parcelableAction)
        }
    }
}