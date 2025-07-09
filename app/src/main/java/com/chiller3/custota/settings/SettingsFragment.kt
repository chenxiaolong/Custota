/*
 * SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota.settings

import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.DocumentsContract
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.net.toUri
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import androidx.preference.get
import androidx.preference.size
import androidx.recyclerview.widget.RecyclerView
import com.chiller3.custota.BuildConfig
import com.chiller3.custota.Permissions
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.dialog.OtaSourceDialogFragment
import com.chiller3.custota.extension.formattedString
import com.chiller3.custota.extension.isGuaranteedLocalFile
import com.chiller3.custota.updater.OtaPaths
import com.chiller3.custota.updater.UpdaterJob
import com.chiller3.custota.updater.UpdaterThread
import com.chiller3.custota.view.LongClickablePreference
import com.chiller3.custota.view.OnPreferenceLongClickListener
import com.chiller3.custota.wrapper.SystemPropertiesProxy
import kotlinx.coroutines.launch
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey


class SettingsFragment : PreferenceFragmentCompat(), Preference.OnPreferenceClickListener,
    OnPreferenceLongClickListener, SharedPreferences.OnSharedPreferenceChangeListener {
    private val viewModel: SettingsViewModel by viewModels()

    private lateinit var prefs: Preferences
    private lateinit var categoryCertificates: PreferenceCategory
    private lateinit var categoryDebug: PreferenceCategory
    private lateinit var prefCheckForUpdates: Preference
    private lateinit var prefOtaSource: LongClickablePreference
    private lateinit var prefUnmeteredOnly: SwitchPreferenceCompat
    private lateinit var prefAndroidVersion: Preference
    private lateinit var prefSecurityPatchLevel: Preference
    private lateinit var prefFingerprint: Preference
    private lateinit var prefVbmetaDigest: Preference
    private lateinit var prefBootSlot: Preference
    private lateinit var prefBootloaderStatus: Preference
    private lateinit var prefNoCertificates: Preference
    private lateinit var prefVersion: LongClickablePreference
    private lateinit var prefOpenLogDir: Preference
    private lateinit var prefRevertCompleted: Preference
    private lateinit var prefInstallCsigCert: Preference

    private lateinit var scheduledAction: UpdaterThread.Action

    private val requestPermissionRequired =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
            if (granted.all { it.key !in Permissions.REQUIRED || it.value }) {
                performAction()
            } else {
                startActivity(Permissions.getAppInfoIntent(requireContext()))
            }
        }
    private val requestSafInstallCsigCert =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let {
                viewModel.installCsigCert(it)
            }
        }

    override fun onCreateRecyclerView(
        inflater: LayoutInflater,
        parent: ViewGroup,
        savedInstanceState: Bundle?
    ): RecyclerView {
        val view = super.onCreateRecyclerView(inflater, parent, savedInstanceState)

        view.clipToPadding = false

        ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )

            // This is a little bit ugly in landscape mode because the divider lines for categories
            // extend into the inset area. However, it's worth applying the left/right padding here
            // anyway because it allows the inset area to be used for scrolling instead of just
            // being a useless dead zone.
            v.updatePadding(
                bottom = insets.bottom,
                left = insets.left,
                right = insets.right,
            )

            WindowInsetsCompat.CONSUMED
        }

        return view
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val context = requireContext()

        preferenceManager.setStorageDeviceProtected()
        setPreferencesFromResource(R.xml.preferences_root, rootKey)

        prefs = Preferences(context)

        categoryCertificates = findPreference(Preferences.CATEGORY_CERTIFICATES)!!
        categoryDebug = findPreference(Preferences.CATEGORY_DEBUG)!!

        prefCheckForUpdates = findPreference(Preferences.PREF_CHECK_FOR_UPDATES)!!
        prefCheckForUpdates.onPreferenceClickListener = this

        prefOtaSource = findPreference(Preferences.PREF_OTA_SOURCE)!!
        prefOtaSource.onPreferenceClickListener = this
        prefOtaSource.onPreferenceLongClickListener = this

        prefUnmeteredOnly = findPreference(Preferences.PREF_UNMETERED_ONLY)!!

        prefAndroidVersion = findPreference(Preferences.PREF_ANDROID_VERSION)!!
        prefAndroidVersion.summary = Build.VERSION.RELEASE

        prefSecurityPatchLevel = findPreference(Preferences.PREF_SECURITY_PATCH_LEVEL)!!
        prefSecurityPatchLevel.summary = SystemPropertiesProxy.get(UpdaterThread.PROP_SECURITY_PATCH)

        prefFingerprint = findPreference(Preferences.PREF_FINGERPRINT)!!
        prefFingerprint.summary = Build.FINGERPRINT

        prefVbmetaDigest = findPreference(Preferences.PREF_VBMETA_DIGEST)!!
        prefVbmetaDigest.summary = SystemPropertiesProxy.get(UpdaterThread.PROP_VBMETA_DIGEST)

        prefBootSlot = findPreference(Preferences.PREF_BOOT_SLOT)!!
        prefBootSlot.summary = SystemPropertiesProxy.get("ro.boot.slot_suffix")
            .removePrefix("_").uppercase()

        prefBootloaderStatus = findPreference(Preferences.PREF_BOOTLOADER_STATUS)!!

        prefNoCertificates = findPreference(Preferences.PREF_NO_CERTIFICATES)!!
        prefNoCertificates.summary = getString(
            R.string.pref_no_certificates_desc, OtaPaths.OTACERTS_ZIP)

        prefVersion = findPreference(Preferences.PREF_VERSION)!!
        prefVersion.onPreferenceClickListener = this
        prefVersion.onPreferenceLongClickListener = this

        prefOpenLogDir = findPreference(Preferences.PREF_OPEN_LOG_DIR)!!
        prefOpenLogDir.onPreferenceClickListener = this

        prefRevertCompleted = findPreference(Preferences.PREF_REVERT_COMPLETED)!!
        prefRevertCompleted.onPreferenceClickListener = this

        prefInstallCsigCert = findPreference(Preferences.PREF_INSTALL_CSIG_CERT)!!
        prefInstallCsigCert.onPreferenceClickListener = this

        refreshCheckForUpdates()
        refreshOtaSource()
        refreshVersion()
        refreshDebugPrefs()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.certs.collect {
                    addCertPreferences(it)
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.bootloaderStatus.collect {
                    if (it != null) {
                        updateBootloaderStatus(it)
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()

        preferenceScreen.sharedPreferences!!.registerOnSharedPreferenceChangeListener(this)

        // Make sure we refresh this every time the user switches back to the app
        viewModel.refreshBootloaderStatus()
    }

    override fun onStop() {
        super.onStop()

        preferenceScreen.sharedPreferences!!.unregisterOnSharedPreferenceChangeListener(this)
    }

    private fun refreshCheckForUpdates() {
        prefCheckForUpdates.isEnabled = prefs.otaSource != null
    }

    private fun refreshOtaSource() {
        prefOtaSource.summary = prefs.otaSource?.formattedString
            ?: getString(R.string.pref_ota_source_none)

        prefUnmeteredOnly.isVisible = prefs.otaSource?.isGuaranteedLocalFile != true
    }

    private fun refreshVersion() {
        val suffix = if (prefs.isDebugMode) {
            "+debugmode"
        } else {
            ""
        }
        prefVersion.summary = "${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_TYPE}${suffix})"
    }

    private fun refreshDebugPrefs() {
        categoryDebug.isVisible = prefs.isDebugMode
    }

    private fun updateBootloaderStatus(status: SettingsViewModel.BootloaderStatus) {
        prefBootloaderStatus.summary = buildString {
            when (status) {
                is SettingsViewModel.BootloaderStatus.Success -> {
                    if (status.unlocked) {
                        append(getString(R.string.pref_bootloader_status_unlocked))
                    } else {
                        append(getString(R.string.pref_bootloader_status_locked))
                    }
                    append('\n')
                    if (status.allowedByCarrier) {
                        append(getString(R.string.pref_bootloader_status_oemlock_carrier_allowed))
                    } else {
                        append(getString(R.string.pref_bootloader_status_oemlock_carrier_blocked))
                    }
                    append('\n')
                    if (status.allowedByUser) {
                        append(getString(R.string.pref_bootloader_status_oemlock_user_allowed))
                    } else {
                        append(getString(R.string.pref_bootloader_status_oemlock_user_blocked))
                    }
                }
                is SettingsViewModel.BootloaderStatus.Failure -> {
                    append(getString(R.string.pref_bootloader_status_unknown))
                    append('\n')
                    append(status.errorMsg)
                }
            }
        }
    }

    private fun performAction() {
        val context = requireContext()

        if (Permissions.haveRequired(context)) {
            UpdaterJob.scheduleImmediate(requireContext(), scheduledAction)
        } else {
            requestPermissionRequired.launch(Permissions.REQUIRED)
        }
    }

    override fun onPreferenceClick(preference: Preference): Boolean {
        when (preference) {
            prefCheckForUpdates -> {
                scheduledAction = UpdaterThread.Action.CHECK
                performAction()
                return true
            }
            prefOtaSource -> {
                OtaSourceDialogFragment().show(parentFragmentManager.beginTransaction(),
                    OtaSourceDialogFragment.TAG)
                return true
            }
            prefVersion -> {
                val uri = BuildConfig.PROJECT_URL_AT_COMMIT.toUri()
                startActivity(Intent(Intent.ACTION_VIEW, uri))
                return true
            }
            prefOpenLogDir -> {
                val externalDir = Environment.getExternalStorageDirectory()
                val filesDir = requireContext().getExternalFilesDir(null)!!
                val relPath = filesDir.relativeTo(externalDir)
                val uri = DocumentsContract.buildDocumentUri(
                    DOCUMENTSUI_AUTHORITY, "primary:$relPath")
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "vnd.android.document/directory")
                }
                startActivity(intent)
                return true
            }
            prefRevertCompleted -> {
                scheduledAction = UpdaterThread.Action.REVERT
                performAction()
                return true
            }
            prefInstallCsigCert -> {
                // See AOSP's frameworks/base/mime/java-res/android.mime.types
                requestSafInstallCsigCert.launch(arrayOf(
                    "application/x-x509-ca-cert",
                    "application/x-x509-user-cert",
                    "application/x-x509-server-cert",
                    "application/x-pem-file",
                ))
                return true
            }
        }

        return false
    }

    override fun onPreferenceLongClick(preference: Preference): Boolean {
        when {
            preference === prefOtaSource -> {
                prefs.otaSource = null
                return true
            }
            preference === prefVersion -> {
                prefs.isDebugMode = !prefs.isDebugMode
                refreshVersion()
                refreshDebugPrefs()
                return true
            }
            preference.key.startsWith(PREF_CERT_PREFIX) -> {
                val index = preference.key.removePrefix(PREF_CERT_PREFIX).toInt()
                viewModel.removeCsigCert(index)
                return true
            }
        }

        return false
    }

    override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences?, key: String?) {
        when (key) {
            Preferences.PREF_OTA_SOURCE -> {
                refreshCheckForUpdates()
                refreshOtaSource()
                UpdaterJob.schedulePeriodic(requireContext(), true)
            }
            Preferences.PREF_AUTOMATIC_CHECK,
            Preferences.PREF_AUTOMATIC_INSTALL,
            Preferences.PREF_UNMETERED_ONLY,
            Preferences.PREF_BATTERY_NOT_LOW -> {
                UpdaterJob.schedulePeriodic(requireContext(), true)
            }
        }
    }

    private fun addCertPreferences(certs: List<Pair<X509Certificate, Boolean>>) {
        val context = requireContext()

        prefNoCertificates.isVisible = certs.isEmpty()

        for (i in (0 until categoryCertificates.size).reversed()) {
            val p = categoryCertificates[i]

            if (p.key.startsWith(PREF_CERT_PREFIX)) {
                categoryCertificates.removePreference(p)
            }
        }

        for ((i, item) in certs.withIndex()) {
            val (cert, isSystem) = item
            val validates = if (isSystem) { "OTA + csig" } else { "csig" }

            val p = LongClickablePreference(context).apply {
                key = PREF_CERT_PREFIX + i
                isPersistent = false
                title = getString(R.string.pref_certificate_name, (i + 1).toString(), validates)
                summary = buildString {
                    append(getString(R.string.pref_certificate_desc_subject,
                        cert.subjectDN.toString()))
                    append('\n')

                    append(getString(R.string.pref_certificate_desc_serial,
                        cert.serialNumber.toString(16)))
                    append('\n')

                    append(getString(R.string.pref_certificate_desc_type, cert.typeName))
                }
                isIconSpaceReserved = false

                if (!isSystem) {
                    onPreferenceLongClickListener = this@SettingsFragment
                }
            }

            categoryCertificates.addPreference(p)
        }
    }

    companion object {
        private const val DOCUMENTSUI_AUTHORITY = "com.android.externalstorage.documents"

        private const val PREF_CERT_PREFIX = "certificate_"

        private val PublicKey.keyLength: Int
            get() {
                when (this) {
                    is ECPublicKey -> params?.order?.bitLength()?.let { return it }
                    is RSAPublicKey -> return modulus.bitLength()
                    is DSAPublicKey -> return if (params != null) {
                        params.p.bitLength()
                    } else {
                        y.bitLength()
                    }
                }

                return -1
            }

        private val Certificate.typeName: String
            get() = buildString {
                append(publicKey.algorithm)
                val keyLength = publicKey.keyLength
                if (keyLength >= 0) {
                    append(' ')
                    append(keyLength)
                }
            }
    }
}
