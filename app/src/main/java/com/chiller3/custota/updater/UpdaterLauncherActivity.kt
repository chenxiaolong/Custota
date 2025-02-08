/*
 * SPDX-FileCopyrightText: 2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import com.chiller3.custota.Permissions
import com.chiller3.custota.settings.SettingsActivity

class UpdaterLauncherActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Permissions.haveRequired(this)) {
            UpdaterJob.scheduleImmediate(this, UpdaterThread.Action.CHECK)
        } else {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        finish()
    }
}
