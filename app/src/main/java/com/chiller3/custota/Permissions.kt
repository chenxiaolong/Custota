/*
 * SPDX-FileCopyrightText: 2022-2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat

object Permissions {
    val NOTIFICATION: Array<String> = arrayOf(Manifest.permission.POST_NOTIFICATIONS)

    val LOCAL_NETWORK: Array<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.CINNAMON_BUN) {
            arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK)
        } else {
            emptyArray()
        }

    /** Check if all permissions have been granted. */
    fun have(context: Context, permissions: Array<String>): Boolean = permissions.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    /** Get intent for opening the app info page in the system settings. */
    fun getAppInfoIntent(context: Context) = Intent(
        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
        Uri.fromParts("package", context.packageName, null),
    )
}
