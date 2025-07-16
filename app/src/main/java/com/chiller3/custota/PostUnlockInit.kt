/*
 * SPDX-FileCopyrightText: 2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota

import android.content.Context
import android.content.Intent
import android.os.UserManager
import android.util.Log
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import com.chiller3.custota.updater.UpdaterJob
import com.chiller3.custota.updater.UpdaterLauncherActivity

object PostUnlockInit {
    private val TAG = PostUnlockInit::class.java.simpleName

    fun initIfUnlocked(context: Context) {
        val userManager = context.getSystemService(UserManager::class.java)
        if (!userManager.isUserUnlocked) {
            Log.w(TAG, "Deferring init until after initial unlock")
            return
        }

        Log.i(TAG, "Initializing items requiring credential-protected storage")

        // Run preferences migrations.
        Preferences(context).let {}

        UpdaterJob.schedulePeriodic(context, false)

        updateShortcuts(context)
    }

    // We don't use static shortcuts because:
    // * There's no way to substitute in the package name. ${applicationId} only works in the
    //   manifest and custom resource definitions are evaluated to @ref/<resource ID>.
    // * When anything breaks, the shortcuts are just silently missing with no error reporting.
    private fun updateShortcuts(context: Context) {
        val icon = IconCompat.createWithResource(context, R.mipmap.ic_launcher)
        val intent = Intent(context, UpdaterLauncherActivity::class.java).apply {
            // Action is required, but value doesn't matter.
            action = Intent.ACTION_MAIN
        }
        val shortcut = ShortcutInfoCompat.Builder(context, Preferences.PREF_CHECK_FOR_UPDATES)
            .setShortLabel(context.getString(R.string.pref_check_for_updates_name))
            .setIcon(icon)
            .setIntent(intent)
            .build()
        val shortcuts = listOf(shortcut)

        if (!ShortcutManagerCompat.setDynamicShortcuts(context, shortcuts)) {
            Log.w(TAG, "Failed to update dynamic shortcuts")
        }
    }
}
