/*
 * SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
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
import android.net.NetworkCapabilities
import android.os.PersistableBundle
import android.util.Log
import com.chiller3.custota.Preferences

class UpdaterJob: JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val prefs = Preferences(this)
        val isPeriodic = params.jobId == ID_PERIODIC

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

        val actionIndex = params.extras.getInt(EXTRA_ACTION, -1)
        val action = UpdaterThread.Action.entries[actionIndex]

        var network = params.network
        if (action.requiresNetwork && network == null) {
            // Ever since the Android 15 betas, Android sometimes invokes this job with a null
            // Network instance, even though the network requirement is set and a sufficient network
            // is available. We'll try to work around this by manually querying the active network.
            // If the active network is insufficient, we'll just abort and wait for the next
            // scheduled run.

            Log.w(TAG, "Job parameters contain a null network instance")

            val connectivityManager = getSystemService(ConnectivityManager::class.java)
            network = connectivityManager.activeNetwork
            if (network == null) {
                Log.w(TAG, "Aborting due to active network also being null")
                return false
            }

            if (prefs.requireUnmetered) {
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                if (capabilities == null) {
                    Log.w(TAG, "Aborting due to the network capabilities being null for: $network")
                    return false
                }

                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) {
                    Log.w(TAG, "Aborting due to active network being metered: $capabilities")
                    return false
                }
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
            action: UpdaterThread.Action,
        ): JobInfo.Builder {
            val prefs = Preferences(context)

            val networkType = if (action.performsLargeDownloads && prefs.requireUnmetered) {
                JobInfo.NETWORK_TYPE_UNMETERED
            } else if (action.requiresNetwork) {
                JobInfo.NETWORK_TYPE_ANY
            } else {
                JobInfo.NETWORK_TYPE_NONE
            }

            val requiresBatteryNotLow = action.usesSignificantBattery && prefs.requireBatteryNotLow

            val extras = PersistableBundle().apply {
                putInt(EXTRA_ACTION, action.ordinal)
            }

            return JobInfo.Builder(jobId, ComponentName(context, UpdaterJob::class.java))
                .setRequiredNetworkType(networkType)
                .setRequiresBatteryNotLow(requiresBatteryNotLow)
                .setExtras(extras)
        }

        private fun bundlesEqual(bundle1: PersistableBundle, bundle2: PersistableBundle): Boolean {
            if (bundle1.keySet() != bundle2.keySet()) {
                return false
            }

            for (key in bundle1.keySet()) {
                // There's no other API for getting an arbitrary value, regardless of type.
                @Suppress("DEPRECATION") val object1 = bundle1.get(key)!!
                @Suppress("DEPRECATION") val object2 = bundle2.get(key)!!

                if (object1 is PersistableBundle && object2 is PersistableBundle) {
                    if (!bundlesEqual(object1, object2)) {
                        return false
                    }
                } else if (object1 is Array<*> && object2 is Array<*>) {
                    if (!object1.contentEquals(object2)) {
                        return false
                    }
                } else if (object1 != object2) {
                    return false
                }
            }

            return true
        }

        private fun JobInfo.toLongString() = buildString {
            append(this)
            append(" {requiredNetwork=")
            append(requiredNetwork)
            append(", isRequiredBatteryNotLow=")
            append(isRequireBatteryNotLow)
            append(", isPersisted=")
            append(isPersisted)
            append(", intervalMillis=")
            append(intervalMillis)
            append(", extras=")
            append(extras)
            append("}")
        }

        private fun scheduleIfUnchanged(context: Context, jobInfo: JobInfo) {
            val jobScheduler = context.getSystemService(JobScheduler::class.java)

            val oldJobInfo = jobScheduler.getPendingJob(jobInfo.id)

            // JobInfo.equals() is unreliable (and the comments in its implementation say so), so
            // just compare the fields that we set.
            if (oldJobInfo != null &&
                oldJobInfo.requiredNetwork == jobInfo.requiredNetwork &&
                oldJobInfo.isRequireBatteryNotLow == jobInfo.isRequireBatteryNotLow &&
                oldJobInfo.isPersisted == jobInfo.isPersisted &&
                oldJobInfo.intervalMillis == jobInfo.intervalMillis &&
                bundlesEqual(oldJobInfo.extras, jobInfo.extras)) {
                Log.i(TAG, "Job already exists and is unchanged: ${jobInfo.toLongString()}")
                return
            }

            Log.d(TAG, "Scheduling job: ${jobInfo.toLongString()}")

            when (val result = jobScheduler.schedule(jobInfo)) {
                JobScheduler.RESULT_SUCCESS ->
                    Log.d(TAG, "Scheduled job: ${jobInfo.toLongString()}")
                JobScheduler.RESULT_FAILURE ->
                    Log.w(TAG, "Failed to schedule job: ${jobInfo.toLongString()}")
                else -> throw IllegalStateException("Unexpected scheduler error: $result")
            }
        }

        fun scheduleImmediate(context: Context, action: UpdaterThread.Action) {
            val jobInfo = createJobBuilder(context, ID_IMMEDIATE, action).build()

            scheduleIfUnchanged(context, jobInfo)
        }

        fun schedulePeriodic(context: Context, skipFirstRun: Boolean) {
            val prefs = Preferences(context)

            val action = if (prefs.automaticInstall) {
                UpdaterThread.Action.INSTALL
            } else {
                UpdaterThread.Action.CHECK
            }

            val jobInfo = createJobBuilder(context, ID_PERIODIC, action)
                .setPersisted(true)
                .setPeriodic(PERIODIC_INTERVAL_MS)
                .build()

            skipNextRun = skipFirstRun

            scheduleIfUnchanged(context, jobInfo)
        }
    }
}