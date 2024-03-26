/*
 * SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.core.content.edit
import androidx.preference.PreferenceManager
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class Preferences(private val context: Context) {
    companion object {
        private val TAG = Preferences::class.java.simpleName

        const val CATEGORY_CERTIFICATES = "certificates"
        const val CATEGORY_DEBUG = "debug"

        const val PREF_CHECK_FOR_UPDATES = "check_for_updates"
        const val PREF_OTA_SOURCE = "ota_source"
        const val PREF_AUTOMATIC_CHECK = "automatic_check"
        const val PREF_AUTOMATIC_INSTALL = "automatic_install"
        const val PREF_UNMETERED_ONLY = "unmetered_only"
        const val PREF_BATTERY_NOT_LOW = "battery_not_low"
        const val PREF_SKIP_POSTINSTALL = "skip_postinstall"
        const val PREF_ANDROID_VERSION = "android_version"
        const val PREF_FINGERPRINT = "fingerprint"
        const val PREF_BOOT_SLOT = "boot_slot"
        const val PREF_BOOTLOADER_STATUS = "bootloader_status"
        const val PREF_NO_CERTIFICATES = "no_certificates"
        const val PREF_VERSION = "version"
        const val PREF_OPEN_LOG_DIR = "open_log_dir"
        const val PREF_ALLOW_REINSTALL = "allow_reinstall"
        const val PREF_REVERT_COMPLETED = "revert_completed"
        const val PREF_INSTALL_CSIG_CERT = "install_csig_cert"

        // Not associated with a UI preference
        private const val PREF_DEBUG_MODE = "debug_mode"
        private const val PREF_CSIG_CERTS = "csig_certs"

        // Legacy preferences
        private const val PREF_OTA_SERVER_URL = "ota_server_url"
    }

    private val prefs = PreferenceManager.getDefaultSharedPreferences(context)

    var isDebugMode: Boolean
        get() = prefs.getBoolean(PREF_DEBUG_MODE, false)
        set(enabled) = prefs.edit { putBoolean(PREF_DEBUG_MODE, enabled) }

    /** Base URI to fetch OTA updates. This is either an HTTP/HTTPS URL or a SAF URI. */
    var otaSource: Uri?
        get() = prefs.getString(PREF_OTA_SOURCE, null)?.let { Uri.parse(it) }
        set(uri) {
            val oldUri = otaSource
            if (oldUri == uri) {
                // URI is the same as before or both are null
                return
            }

            prefs.edit {
                if (uri != null) {
                    if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
                        // Persist permissions for the new URI first
                        context.contentResolver.takePersistableUriPermission(
                            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }

                    putString(PREF_OTA_SOURCE, uri.toString())
                } else {
                    remove(PREF_OTA_SOURCE)
                }
            }

            // Release persisted permissions on the old directory only after the new URI is set to
            // guarantee atomicity
            if (oldUri != null && oldUri.scheme == ContentResolver.SCHEME_CONTENT) {
                // It's not documented, but this can throw an exception when trying to release a
                // previously persisted URI that's associated with an app that's no longer installed
                try {
                    context.contentResolver.releasePersistableUriPermission(
                        oldUri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                } catch (e: Exception) {
                    Log.w(TAG, "Error when releasing persisted URI permission for: $oldUri", e)
                }
            }
        }

    /** Whether to check for updates periodically. */
    var automaticCheck: Boolean
        get() = prefs.getBoolean(PREF_AUTOMATIC_CHECK, true)
        set(enabled) = prefs.edit { putBoolean(PREF_AUTOMATIC_CHECK, enabled) }

    /** Whether to install updates in the periodic job or just check for them. */
    var automaticInstall: Boolean
        get() = prefs.getBoolean(PREF_AUTOMATIC_INSTALL, false)
        set(enabled) = prefs.edit { putBoolean(PREF_AUTOMATIC_INSTALL, enabled) }

    /** Whether to only allow running when connected to an unmetered network. */
    var requireUnmetered: Boolean
        get() = prefs.getBoolean(PREF_UNMETERED_ONLY, true)
        set(enabled) = prefs.edit { putBoolean(PREF_UNMETERED_ONLY, enabled) }

    /** Whether to only allow running when battery is above the critical threshold. */
    var requireBatteryNotLow: Boolean
        get() = prefs.getBoolean(PREF_BATTERY_NOT_LOW, true)
        set(enabled) = prefs.edit { putBoolean(PREF_BATTERY_NOT_LOW, enabled) }

    /** Whether to skip optional post-install scripts in the OTA. */
    var skipPostInstall: Boolean
        get() = prefs.getBoolean(PREF_SKIP_POSTINSTALL, false)
        set(enabled) = prefs.edit { putBoolean(PREF_SKIP_POSTINSTALL, enabled) }

    /** Whether to treat an equal fingerprint as an update. */
    var allowReinstall: Boolean
        get() = prefs.getBoolean(PREF_ALLOW_REINSTALL, false)
        set(enabled) = prefs.edit { putBoolean(PREF_ALLOW_REINSTALL, enabled) }

    var csigCerts: Set<X509Certificate>
        get() {
            val encoded = prefs.getStringSet(PREF_CSIG_CERTS, emptySet())!!
            val factory = CertificateFactory.getInstance("X.509")

            return encoded
                .asSequence()
                .map { base64 ->
                    val der = Base64.decode(base64, Base64.DEFAULT)

                    ByteArrayInputStream(der).use {
                        factory.generateCertificate(it) as X509Certificate
                    }
                }
                .toSet()
        }
        set(certs) {
            val encoded = certs
                .asSequence()
                .map {
                    Base64.encodeToString(it.encoded, Base64.NO_WRAP)
                }
                .toSet()

            prefs.edit { putStringSet(PREF_CSIG_CERTS, encoded) }
        }

    /** Migrate legacy preferences to current preferences. */
    fun migrate() {
        if (prefs.contains(PREF_OTA_SERVER_URL)) {
            otaSource = prefs.getString(PREF_OTA_SERVER_URL, null)?.let { Uri.parse(it) }
            prefs.edit { remove(PREF_OTA_SERVER_URL) }
        }
    }
}
