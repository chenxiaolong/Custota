/*
 * Copyright (C) 2022-2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
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

        UpdaterJob.schedulePeriodic(this, false)
    }

    companion object {
        private val TAG = MainApplication::class.java.simpleName
    }
}
