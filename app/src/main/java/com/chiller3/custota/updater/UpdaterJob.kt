/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.os.PersistableBundle
import android.util.Log
import androidx.annotation.StringRes
import com.chiller3.custota.Notifications
import com.chiller3.custota.Preferences
import com.chiller3.custota.R

class UpdaterJob: JobService() {
    private fun notifyAlert(@StringRes messageId: Int) {
        val notifications = Notifications(this)
        notifications.sendAlertNotification(
            Notifications.CHANNEL_ID_FAILURE,
            true,
            R.string.notification_update_init_failed,
            R.drawable.ic_notifications,
            getString(messageId),
            emptyList()
        )
    }

    override fun onStartJob(params: JobParameters): Boolean {
        val prefs = Preferences(this)

        val actionIndex = params.extras.getInt(EXTRA_ACTION, -1)
        val isPeriodic = actionIndex == -1

        if (isPeriodic) {
            if (!prefs.automaticCheck) {
                Log.i(TAG, "Automatic update checks are disabled")
                return false
            } else if (skipNextRun) {
                Log.i(TAG, "Skipped this run of the periodic job")
                skipNextRun = false
                return false
            }
        }

        val action = if (!isPeriodic) {
            UpdaterThread.Action.entries[actionIndex]
        } else if (prefs.automaticInstall) {
            UpdaterThread.Action.INSTALL
        } else {
            UpdaterThread.Action.CHECK
        }

        var network = params.network
        if (network == null) {
            // This was reported to happen on the Android 15 beta.
            Log.w(TAG, "Job parameters contain a null network instance")

            if (prefs.requireUnmetered) {
                Log.w(TAG, "Aborting due to require unmetered network option")
                notifyAlert(R.string.notification_null_network_fallback)
                return false
            }

            val connectivityManager = getSystemService(ConnectivityManager::class.java)
            network = connectivityManager.activeNetwork
            if (network == null) {
                Log.e(TAG, "Aborting due to active network also being null")
                notifyAlert(R.string.notification_null_network_unavailable)
                return false
            }
        }

        startForegroundService(UpdaterService.createStartIntent(
            applicationContext, network, action, isPeriodic))
        return false
    }

    override fun onStopJob(params: JobParameters): Boolean {
        return false
    }

    companion object {
        private val TAG = UpdaterJob::class.java.simpleName

        private const val ID_IMMEDIATE = 1
        private const val ID_PERIODIC = 2

        private const val EXTRA_ACTION = "action"

        private const val PERIODIC_INTERVAL_MS = 6L * 60 * 60 * 1000

        // Scheduling a periodic job usually makes the first iteration run immediately. We'll
        // sometimes skip this to avoid unexpected operations while the user is configuring
        // settings in the UI.
        private var skipNextRun = false

        private fun createJobBuilder(
            context: Context,
            jobId: Int,
            action: UpdaterThread.Action?,
        ): JobInfo.Builder {
            val prefs = Preferences(context)

            val networkType = if (prefs.requireUnmetered) {
                JobInfo.NETWORK_TYPE_UNMETERED
            } else {
                JobInfo.NETWORK_TYPE_ANY
            }

            val extras = PersistableBundle().apply {
                if (action != null) {
                    putInt(EXTRA_ACTION, action.ordinal)
                }
            }

            return JobInfo.Builder(jobId, ComponentName(context, UpdaterJob::class.java))
                .setRequiredNetworkType(networkType)
                .setRequiresBatteryNotLow(prefs.requireBatteryNotLow)
                .setExtras(extras)
        }

        private fun scheduleIfUnchanged(context: Context, jobInfo: JobInfo) {
            val jobScheduler = context.getSystemService(JobScheduler::class.java)

            val oldJobInfo = jobScheduler.getPendingJob(jobInfo.id)

            // JobInfo.equals() is unreliable (and the comments in its implementation say so), so
            // just compare the fields that we set. We don't compare the extras because there's no
            // sane way to do so. That doesn't matter for our use case because this check is mostly
            // useful for the periodic job, which doesn't use extras.
            if (oldJobInfo != null &&
                oldJobInfo.requiredNetwork == jobInfo.requiredNetwork &&
                oldJobInfo.isRequireBatteryNotLow == jobInfo.isRequireBatteryNotLow &&
                oldJobInfo.isPersisted == jobInfo.isPersisted &&
                oldJobInfo.intervalMillis == jobInfo.intervalMillis) {
                Log.i(TAG, "Job already exists and is unchanged: $jobInfo")
                return
            }

            Log.d(TAG, "Scheduling job: $jobInfo")

            when (val result = jobScheduler.schedule(jobInfo)) {
                JobScheduler.RESULT_SUCCESS ->
                    Log.d(TAG, "Scheduled job: $jobInfo")
                JobScheduler.RESULT_FAILURE ->
                    Log.w(TAG, "Failed to schedule job: $jobInfo")
                else -> throw IllegalStateException("Unexpected scheduler error: $result")
            }
        }

        fun scheduleImmediate(context: Context, action: UpdaterThread.Action) {
            val jobInfo = createJobBuilder(context, ID_IMMEDIATE, action).build()

            scheduleIfUnchanged(context, jobInfo)
        }

        fun schedulePeriodic(context: Context, skipFirstRun: Boolean) {
            val jobInfo = createJobBuilder(context, ID_PERIODIC, null)
                .setPersisted(true)
                .setPeriodic(PERIODIC_INTERVAL_MS)
                .build()

            skipNextRun = skipFirstRun

            scheduleIfUnchanged(context, jobInfo)
        }
    }
}