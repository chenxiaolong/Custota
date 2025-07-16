/*
 * SPDX-FileCopyrightText: 2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PostUnlockInitReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }

        PostUnlockInit.initIfUnlocked(context)
    }
}
