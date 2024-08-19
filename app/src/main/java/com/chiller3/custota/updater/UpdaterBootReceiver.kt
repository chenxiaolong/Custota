/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class UpdaterBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }

        // This will monitor the cleanup process on the reboot immediately following an OTA.
        UpdaterJob.scheduleImmediate(context, UpdaterThread.Action.CHECK)
    }
}
