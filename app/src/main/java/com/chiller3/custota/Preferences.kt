/*
 * SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.UserManager
import android.util.Base64
import android.util.Log
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.preference.PreferenceManager
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class Preferences(initialContext: Context) {
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
        const val PREF_SECURITY_PATCH_LEVEL = "security_patch_level"
        const val PREF_FINGERPRINT = "fingerprint"
        const val PREF_VBMETA_DIGEST = "vbmeta_digest"
        const val PREF_BOOT_SLOT = "boot_slot"
        const val PREF_BOOTLOADER_STATUS = "bootloader_status"
        const val PREF_NO_CERTIFICATES = "no_certificates"
        const val PREF_VERSION = "version"
        const val PREF_OPEN_LOG_DIR = "open_log_dir"
        const val PREF_ALLOW_REINSTALL = "allow_reinstall"
        const val PREF_REVERT_COMPLETED = "revert_completed"
        const val PREF_INSTALL_CSIG_CERT = "install_csig_cert"
        const val PREF_PIN_NETWORK_ID = "pin_network_id"

        // Not associated with a UI preference
        private const val PREF_DEBUG_MODE = "debug_mode"
        private const val PREF_CSIG_CERTS = "csig_certs"
        private const val PREF_ALREADY_MIGRATED = "already_migrated"

        // Legacy preferences
        private const val PREF_OTA_SERVER_URL = "ota_server_url"

        private fun migrateToDeviceProtectedStorage(context: Context) {
            synchronized(this) {
                if (context.isDeviceProtectedStorage) {
                    Log.w(TAG, "Cannot migrate without credential-protected storage context")
                    return
                }

                val userManager = context.getSystemService(UserManager::class.java)
                if (!userManager.isUserUnlocked) {
                    Log.w(TAG, "Cannot migrate preferences in BFU state")
                    return
                }

                val deviceContext = context.createDeviceProtectedStorageContext()
                var devicePrefs = PreferenceManager.getDefaultSharedPreferences(deviceContext)

                // getDefaultSharedPreferencesName() is not public, but realistically, Android can't
                // ever change the default shared preferences name without breaking nearly every app.
                val sharedPreferencesName = context.packageName + "_preferences"

                if (devicePrefs.getBoolean(PREF_ALREADY_MIGRATED, false)) {
                    val oldPrefsFile =
                        File(File(context.dataDir, "shared_prefs"), "$sharedPreferencesName.xml")
                    if (!oldPrefsFile.exists()) {
                        Log.i(TAG, "Already migrated preferences to device protected storage")
                        return
                    } else if (devicePrefs.getString(PREF_OTA_SOURCE, null) != null) {
                        Log.i(TAG, "User already reconfigured app following botched migration")
                        context.deleteSharedPreferences(sharedPreferencesName)
                        return
                    } else {
                        Log.i(TAG, "Reattempting migration after regression")
                    }
                }

                Log.i(TAG, "Migrating preferences to device-protected storage")

                // This returns true if the shared preferences didn't exist.
                if (!deviceContext.moveSharedPreferencesFrom(context, sharedPreferencesName)) {
                    Log.e(TAG, "Failed to migrate preferences to device protected storage")
                    return
                }

                devicePrefs = PreferenceManager.getDefaultSharedPreferences(deviceContext)
                devicePrefs.edit { putBoolean(PREF_ALREADY_MIGRATED, true) }
            }
        }
    }

    init {
        migrateToDeviceProtectedStorage(initialContext)
    }

    private val context = if (initialContext.isDeviceProtectedStorage) {
        initialContext
    } else {
        initialContext.createDeviceProtectedStorageContext()
    }
    private val prefs = PreferenceManager.getDefaultSharedPreferences(context)

    init {
        migrate()
    }

    var isDebugMode: Boolean
        get() = prefs.getBoolean(PREF_DEBUG_MODE, false)
        set(enabled) = prefs.edit { putBoolean(PREF_DEBUG_MODE, enabled) }

    /** Base URI to fetch OTA updates. This is either an HTTP/HTTPS URL or a SAF URI. */
    var otaSource: Uri?
        get() = prefs.getString(PREF_OTA_SOURCE, null)?.toUri()
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

    /** Whether to pin all connections to a specific network ID. */
    var pinNetworkId: Boolean
        get() = prefs.getBoolean(PREF_PIN_NETWORK_ID, true)
        set(enabled) = prefs.edit { putBoolean(PREF_PIN_NETWORK_ID, enabled) }

    /** Migrate legacy preferences to current preferences. */
    private fun migrate() {
        if (prefs.contains(PREF_OTA_SERVER_URL)) {
            otaSource = prefs.getString(PREF_OTA_SERVER_URL, null)?.toUri()
            prefs.edit { remove(PREF_OTA_SERVER_URL) }
        }
    }
}
