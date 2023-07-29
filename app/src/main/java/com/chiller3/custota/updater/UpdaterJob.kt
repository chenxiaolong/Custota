/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * This file is part of Custota.
 *
 * Custota is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * Custota is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Custota.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.chiller3.custota.updater

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.PersistableBundle
import android.util.Log
import com.chiller3.custota.Preferences

class UpdaterJob: JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val prefs = Preferences(this)

        val actionIndex = params.extras.getInt(EXTRA_ACTION, -1)
        val isPeriodic = actionIndex == -1

        val action = if (!isPeriodic) {
            UpdaterThread.Action.values()[actionIndex]
        } else if (prefs.automaticInstall) {
            UpdaterThread.Action.INSTALL
        } else {
            UpdaterThread.Action.CHECK
        }

        startForegroundService(UpdaterService.createStartIntent(
            applicationContext, params.network!!, action, isPeriodic))
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

        fun schedulePeriodic(context: Context) {
            val jobInfo = createJobBuilder(context, ID_PERIODIC, null)
                .setPersisted(true)
                .setPeriodic(PERIODIC_INTERVAL_MS)
                .build()

            scheduleIfUnchanged(context, jobInfo)
        }
    }
}