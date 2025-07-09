/*
 * SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota

import android.app.Application
import android.content.Intent
import android.os.UserManager
import android.util.Log
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import com.chiller3.custota.updater.UpdaterJob
import com.chiller3.custota.updater.UpdaterLauncherActivity
import com.google.android.material.color.DynamicColors
import java.io.File

class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        val oldCrashHandler = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                getExternalFilesDir(null)?.let { externalFilesDir ->
                    val logcatFile = File(externalFilesDir, "crash.log")

                    Log.e(TAG, "Saving logcat to $logcatFile due to uncaught exception in $t", e)

                    ProcessBuilder("logcat", "-d", "*:V")
                        .redirectOutput(logcatFile)
                        .redirectErrorStream(true)
                        .start()
                        .waitFor()
                }
            } finally {
                oldCrashHandler?.uncaughtException(t, e)
            }
        }

        // Enable Material You colors
        DynamicColors.applyToActivitiesIfAvailable(this)

        // Move preferences to device-protected storage for direct boot support.
        Preferences.migrateToDeviceProtectedStorage(this)

        Preferences(this).migrate()

        Notifications(this).updateChannels()

        UpdaterJob.schedulePeriodic(this, false)

        updateShortcuts()
    }

    // We don't use static shortcuts because:
    // * There's no way to substitute in the package name. ${applicationId} only works in the
    //   manifest and custom resource definitions are evaluated to @ref/<resource ID>.
    // * When anything breaks, the shortcuts are just silently missing with no error reporting.
    private fun updateShortcuts() {
        val userManager = getSystemService(UserManager::class.java)
        if (!userManager.isUserUnlocked) {
            // We currently don't trigger anything when the user unlocks the device. It'll happen
            // eventually when the app is unloaded from memory and the user reopens it or the
            // scheduled job runs.
            Log.w(TAG, "Cannot update dynamic shortcuts until unlocked")
            return
        }

        val icon = IconCompat.createWithResource(this, R.mipmap.ic_launcher)
        val intent = Intent(this, UpdaterLauncherActivity::class.java).apply {
            // Action is required, but value doesn't matter.
            action = Intent.ACTION_MAIN
        }
        val shortcut = ShortcutInfoCompat.Builder(this, Preferences.PREF_CHECK_FOR_UPDATES)
            .setShortLabel(getString(R.string.pref_check_for_updates_name))
            .setIcon(icon)
            .setIntent(intent)
            .build()
        val shortcuts = listOf(shortcut)

        if (!ShortcutManagerCompat.setDynamicShortcuts(this, shortcuts)) {
            Log.w(TAG, "Failed to update dynamic shortcuts")
        }
    }

    companion object {
        private val TAG = MainApplication::class.java.simpleName
    }
}
