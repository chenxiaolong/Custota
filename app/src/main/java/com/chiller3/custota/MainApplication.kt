/*
 * Copyright (C) 2022-2023  Andrew Gunnerson
 *
 * This file is part of Custota, based on BCR code.
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

package com.chiller3.custota

import android.app.Application
import android.util.Log
import com.chiller3.custota.updater.UpdaterJob
import com.google.android.material.color.DynamicColors
import java.io.File

class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        val oldCrashHandler = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val logcatFile = File(getExternalFilesDir(null), "crash.log")

                Log.e(TAG, "Saving logcat to $logcatFile due to uncaught exception in $t", e)

                ProcessBuilder("logcat", "-d", "*:V")
                    .redirectOutput(logcatFile)
                    .redirectErrorStream(true)
                    .start()
                    .waitFor()
            } finally {
                oldCrashHandler?.uncaughtException(t, e)
            }
        }

        // Enable Material You colors
        DynamicColors.applyToActivitiesIfAvailable(this)

        Notifications(this).updateChannels()

        UpdaterJob.schedulePeriodic(this)
    }

    companion object {
        private val TAG = MainApplication::class.java.simpleName
    }
}
