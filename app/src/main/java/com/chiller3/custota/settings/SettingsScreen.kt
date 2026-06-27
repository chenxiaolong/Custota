/*
 * SPDX-FileCopyrightText: 2022-2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.settings

import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.core.net.toUri
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.chiller3.custota.BuildConfig
import com.chiller3.custota.Permissions
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.extension.EXTERNAL_STORAGE_AUTHORITY
import com.chiller3.custota.extension.formattedString
import com.chiller3.custota.extension.isGuaranteedLocalFile
import com.chiller3.custota.ui.AppScreen
import com.chiller3.custota.ui.BetterSegmentedShapes
import com.chiller3.custota.ui.Preference
import com.chiller3.custota.ui.PreferenceCategory
import com.chiller3.custota.ui.PreferenceColumn
import com.chiller3.custota.ui.SwitchPreference
import com.chiller3.custota.ui.betterSegmentedShapes
import com.chiller3.custota.ui.theme.AppTheme
import com.chiller3.custota.updater.OtaPaths
import com.chiller3.custota.updater.UpdaterJob
import com.chiller3.custota.updater.UpdaterThread
import com.chiller3.custota.wrapper.SystemPropertiesProxy
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

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

@Composable
fun SettingsScreen(viewModel: SettingsViewModel = viewModel()) {
    val context = LocalContext.current
    val resources = LocalResources.current

    val prefs = remember { Preferences(context) }
    var reloadPrefs by remember { mutableIntStateOf(0) }
    val otaSource = remember(reloadPrefs) { prefs.otaSource }
    val automaticCheck = remember(reloadPrefs) { prefs.automaticCheck }
    val automaticInstall = remember(reloadPrefs) { prefs.automaticInstall }
    val requireUnmetered = remember(reloadPrefs) { prefs.requireUnmetered }
    val requireBatteryNotLow = remember(reloadPrefs) { prefs.requireBatteryNotLow }
    val isDebugMode = remember(reloadPrefs) { prefs.isDebugMode }
    val skipPostInstall = remember(reloadPrefs) { prefs.skipPostInstall }
    val allowReinstall = remember(reloadPrefs) { prefs.allowReinstall }
    val pinNetworkId = remember(reloadPrefs) { prefs.pinNetworkId }

    var reloadPerms by remember { mutableIntStateOf(0) }
    val localNetworkGranted = remember(reloadPerms) {
        Permissions.have(context, Permissions.LOCAL_NETWORK)
    }

    val bootloaderStatus by viewModel.bootloaderStatus.collectAsStateWithLifecycle()
    val certificates by viewModel.certificates.collectAsStateWithLifecycle()

    var scheduledAction by rememberSaveable { mutableStateOf<UpdaterThread.Action?>(null) }
    val performAction = {
        if (Permissions.have(context, Permissions.NOTIFICATION)) {
            UpdaterJob.scheduleImmediate(context, scheduledAction!!)
            scheduledAction = null
            true
        } else {
            false
        }
    }

    val requestPermissionsRequired = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        if (granted.all { it.value }) {
            reloadPerms++

            if (scheduledAction != null) {
                performAction()
            }
        } else {
            context.startActivity(Permissions.getAppInfoIntent(context))
        }
    }

    val performActionOrRequestPermissions = {
        if (!performAction()) {
            requestPermissionsRequired.launch(Permissions.NOTIFICATION)
        }
    }

    val requestSafInstallCsigCert = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let {
            viewModel.installCsigCert(it)
        }
    }

    var showErrorDialog by rememberSaveable { mutableStateOf<String?>(null) }

    AppScreen(
        title = { Text(text = stringResource(R.string.app_name)) },
    ) { params ->
        LaunchedEffect(Unit) {
            viewModel.alerts.collect { alerts ->
                val alert = alerts.firstOrNull() ?: return@collect
                val msg = when (alert) {
                    is Alert.SystemCertLoadFailure ->
                        resources.getString(R.string.alert_system_cert_load_failure)
                    is Alert.CsigCertLoadFailure ->
                        resources.getString(R.string.alert_csig_cert_load_failure)
                    Alert.BrowserNotFound ->
                        resources.getString(R.string.alert_browser_not_found)
                    Alert.DocumentsUINotFound ->
                        resources.getString(R.string.alert_documentsui_not_found)
                }
                val details = when (alert) {
                    is Alert.SystemCertLoadFailure -> alert.error
                    is Alert.CsigCertLoadFailure -> alert.error
                    Alert.BrowserNotFound -> null
                    Alert.DocumentsUINotFound -> null
                }

                val result = params.snackbarHostState.showSnackbar(
                    message = msg,
                    details?.let { resources.getString(R.string.action_details) },
                    withDismissAction = true,
                )
                viewModel.acknowledgeFirstAlert()

                when (result) {
                    SnackbarResult.Dismissed -> {}
                    SnackbarResult.ActionPerformed -> { showErrorDialog = details }
                }
            }
        }

        showErrorDialog?.let { message ->
            ErrorDetailsDialog(
                message = message,
                onDismiss = { showErrorDialog = null },
            )
        }

        SettingsContent(
            otaSource = otaSource,
            automaticCheck = automaticCheck,
            automaticInstall = automaticInstall,
            requireUnmetered = requireUnmetered,
            requireBatteryNotLow = requireBatteryNotLow,
            skipPostInstall = skipPostInstall,
            localNetworkGranted = localNetworkGranted,
            androidVersion = Build.VERSION.RELEASE,
            securityPatchLevel = SystemPropertiesProxy.get(UpdaterThread.PROP_SECURITY_PATCH),
            fingerprint = Build.FINGERPRINT,
            vbmetaDigest = SystemPropertiesProxy.get(UpdaterThread.PROP_VBMETA_DIGEST),
            bootSlot = SystemPropertiesProxy.get("ro.boot.slot_suffix")
                .removePrefix("_").uppercase(),
            bootloaderStatus = bootloaderStatus,
            certificates = certificates,
            isDebugMode = isDebugMode,
            allowReinstall = allowReinstall,
            pinNetworkId = pinNetworkId,
            onCheckForUpdates = {
                scheduledAction = UpdaterThread.Action.CHECK
                performActionOrRequestPermissions()
            },
            onOtaSourceChange = { uri ->
                prefs.otaSource = uri
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onOtaSourceReset = {
                prefs.otaSource = null
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onAutomaticCheckChange = { enabled ->
                prefs.automaticCheck = enabled
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onAutomaticInstallChange = { enabled ->
                prefs.automaticInstall = enabled
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onRequireUnmeteredChange = { enabled ->
                prefs.requireUnmetered = enabled
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onRequireBatteryNotLowChange = { enabled ->
                prefs.requireBatteryNotLow = enabled
                reloadPrefs++
                UpdaterJob.schedulePeriodic(context, true)
            },
            onSkipPostInstallChange = { enabled ->
                prefs.skipPostInstall = enabled
                reloadPrefs++
            },
            onLocalNetworkGrant = {
                requestPermissionsRequired.launch(Permissions.LOCAL_NETWORK)
            },
            onCsigCertRemove = { certificate ->
                viewModel.removeCsigCert(certificate)
            },
            onSourceRepoOpen = {
                val uri = BuildConfig.PROJECT_URL_AT_COMMIT.toUri()
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, uri))
                } catch (_: ActivityNotFoundException) {
                    viewModel.addAlert(Alert.BrowserNotFound)
                }
            },
            onDebugModeChange = { enabled ->
                prefs.isDebugMode = enabled
                reloadPrefs++
            },
            onOpenLogDir = {
                val externalDir = Environment.getExternalStorageDirectory()
                val filesDir = context.getExternalFilesDir(null)!!
                val relPath = filesDir.relativeTo(externalDir)
                val uri = DocumentsContract.buildDocumentUri(
                    EXTERNAL_STORAGE_AUTHORITY, "primary:$relPath")
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "vnd.android.document/directory")
                }

                try {
                    context.startActivity(intent)
                } catch (_: ActivityNotFoundException) {
                    viewModel.addAlert(Alert.DocumentsUINotFound)
                }
            },
            onAllowReinstallChange = { enabled ->
                prefs.allowReinstall = enabled
                reloadPrefs++
            },
            onRevertCompleted = {
                scheduledAction = UpdaterThread.Action.REVERT
                performActionOrRequestPermissions()
            },
            onCsigCertInstall = {
                // See AOSP's frameworks/base/mime/java-res/android.mime.types
                requestSafInstallCsigCert.launch(arrayOf(
                    "application/x-x509-ca-cert",
                    "application/x-x509-user-cert",
                    "application/x-x509-server-cert",
                    "application/x-pem-file",
                ))
            },
            onPinNetworkIdChange = { enabled ->
                prefs.pinNetworkId = enabled
                reloadPrefs++
            },
            contentPadding = params.contentPadding,
        )
    }

    LifecycleResumeEffect(Unit) {
        // Make sure we refresh this every time the user switches back to the app.
        viewModel.refreshBootloaderStatus()

        onPauseOrDispose {}
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun SettingsContent(
    otaSource: Uri?,
    automaticCheck: Boolean,
    automaticInstall: Boolean,
    requireUnmetered: Boolean,
    requireBatteryNotLow: Boolean,
    skipPostInstall: Boolean,
    localNetworkGranted: Boolean,
    androidVersion: String,
    securityPatchLevel: String,
    fingerprint: String,
    vbmetaDigest: String,
    bootSlot: String,
    bootloaderStatus: SettingsViewModel.BootloaderStatus?,
    certificates: List<Pair<X509Certificate, Boolean>>,
    isDebugMode: Boolean,
    allowReinstall: Boolean,
    pinNetworkId: Boolean,
    onCheckForUpdates: () -> Unit,
    onOtaSourceChange: (Uri) -> Unit,
    onOtaSourceReset: () -> Unit,
    onAutomaticCheckChange: (Boolean) -> Unit,
    onAutomaticInstallChange: (Boolean) -> Unit,
    onRequireUnmeteredChange: (Boolean) -> Unit,
    onRequireBatteryNotLowChange: (Boolean) -> Unit,
    onSkipPostInstallChange: (Boolean) -> Unit,
    onLocalNetworkGrant: () -> Unit,
    onCsigCertRemove: (X509Certificate) -> Unit,
    onSourceRepoOpen: () -> Unit,
    onDebugModeChange: (Boolean) -> Unit,
    onOpenLogDir: () -> Unit,
    onAllowReinstallChange: (Boolean) -> Unit,
    onRevertCompleted: () -> Unit,
    onCsigCertInstall: () -> Unit,
    onPinNetworkIdChange: (Boolean) -> Unit,
    contentPadding: PaddingValues = PaddingValues(),
) {
    data class MissingPermission(
        val key: String,
        val title: String,
        val summary: String,
        val onGrant: () -> Unit,
    )

    val missingPermissions = mutableListOf<MissingPermission>().apply {
        if (!localNetworkGranted) {
            add(MissingPermission(
                key = "allow_local_network",
                title = stringResource(R.string.pref_allow_local_network_name),
                summary = stringResource(R.string.pref_allow_local_network_desc),
                onGrant = onLocalNetworkGrant,
            ))
        }
    }

    var showOtaSourceDialog by rememberSaveable { mutableStateOf(false) }

    PreferenceColumn(contentPadding = contentPadding) {
        item(key = "general") {
            PreferenceCategory(
                title = { Text(text = stringResource(R.string.pref_header_general)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "check_for_updates") {
            Preference(
                onClick = onCheckForUpdates,
                enabled = otaSource != null,
                shapes = BetterSegmentedShapes.top(),
                title = { Text(text = stringResource(R.string.pref_check_for_updates_name)) },
                summary = { Text(text = stringResource(R.string.pref_check_for_updates_desc)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "ota_source") {
            Preference(
                onClick = { showOtaSourceDialog = true },
                onLongClick = onOtaSourceReset,
                shapes = BetterSegmentedShapes.bottom(),
                title = { Text(text = stringResource(R.string.pref_ota_source_name)) },
                summary = { Text(text = otaSourceSummary(otaSource)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "behavior") {
            PreferenceCategory(
                title = { Text(text = stringResource(R.string.pref_header_behavior)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "automatic_check") {
            SwitchPreference(
                checked = automaticCheck,
                onCheckedChange = onAutomaticCheckChange,
                shapes = BetterSegmentedShapes.top(),
                title = { Text(text = stringResource(R.string.pref_automatic_check_name)) },
                summary = { Text(text = stringResource(R.string.pref_automatic_check_desc)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "automatic_install") {
            SwitchPreference(
                checked = automaticInstall,
                onCheckedChange = onAutomaticInstallChange,
                enabled = automaticCheck,
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_automatic_install_name)) },
                summary = { Text(text = stringResource(R.string.pref_automatic_install_desc)) },
                modifier = Modifier.animateItem(),
            )
        }

        if (otaSource?.isGuaranteedLocalFile != true) {
            item(key = "unmetered_only") {
                SwitchPreference(
                    checked = requireUnmetered,
                    onCheckedChange = onRequireUnmeteredChange,
                    shapes = BetterSegmentedShapes.middle(),
                    title = { Text(text = stringResource(R.string.pref_unmetered_only_name)) },
                    summary = { Text(text = stringResource(R.string.pref_unmetered_only_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }
        }

        item(key = "battery_not_low") {
            SwitchPreference(
                checked = requireBatteryNotLow,
                onCheckedChange = onRequireBatteryNotLowChange,
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_battery_not_low_name)) },
                summary = { Text(text = stringResource(R.string.pref_battery_not_low_desc)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "skip_postinstall") {
            SwitchPreference(
                checked = skipPostInstall,
                onCheckedChange = onSkipPostInstallChange,
                shapes = BetterSegmentedShapes.bottom(),
                title = { Text(text = stringResource(R.string.pref_skip_postinstall_name)) },
                summary = { Text(text = stringResource(R.string.pref_skip_postinstall_desc)) },
                modifier = Modifier.animateItem(),
            )
        }

        if (missingPermissions.isNotEmpty()) {
            item(key = "permissions") {
                PreferenceCategory(
                    title = { Text(text = stringResource(R.string.pref_header_permissions)) },
                    modifier = Modifier.animateItem(),
                )
            }

            itemsIndexed(missingPermissions, key = { _, m -> m.key }) { index, missing ->
                Preference(
                    onClick = missing.onGrant,
                    shapes = betterSegmentedShapes(index, missingPermissions.size),
                    title = { Text(text = missing.title) },
                    summary = { Text(text = missing.summary) },
                    modifier = Modifier.animateItem(),
                )
            }
        }

        item(key = "os") {
            PreferenceCategory(
                title = { Text(text = stringResource(R.string.pref_header_os)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "android_version") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.top(),
                title = { Text(text = stringResource(R.string.pref_android_version_name)) },
                summary = { Text(text = androidVersion) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "security_patch_level") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_security_patch_level_name)) },
                summary = { Text(text = securityPatchLevel) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "fingerprint") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_fingerprint_name)) },
                summary = { Text(text = fingerprint) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "vbmeta_digest") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_vbmeta_digest_name)) },
                summary = { Text(text = vbmetaDigest) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "boot_slot") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.middle(),
                title = { Text(text = stringResource(R.string.pref_boot_slot_name)) },
                summary = { Text(text = bootSlot) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "bootloader_status") {
            Preference(
                onClick = {},
                shapes = BetterSegmentedShapes.bottom(),
                title = { Text(text = stringResource(R.string.pref_bootloader_status_name)) },
                summary = { bootloaderStatus?.let { Text(text = bootloaderStatusSummary(it)) } },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "certificates") {
            PreferenceCategory(
                title = { Text(text = stringResource(R.string.pref_header_certificates)) },
                modifier = Modifier.animateItem(),
            )
        }

        if (certificates.isEmpty()) {
            item(key = "no_certificates") {
                val summary = stringResource(
                    R.string.pref_no_certificates_desc,
                    OtaPaths.OTACERTS_ZIP,
                )

                Preference(
                    onClick = {},
                    enabled = false,
                    shapes = BetterSegmentedShapes.single(),
                    title = { Text(text = stringResource(R.string.pref_no_certificates_name)) },
                    summary = { Text(text = summary) },
                    modifier = Modifier.animateItem(),
                )
            }
        } else {
            itemsIndexed(certificates, key = { _, (c, _) -> c }) { index, (certificate, isSystem) ->
                val onLongClick = if (isSystem) {
                    null
                } else {
                    { onCsigCertRemove(certificate) }
                }

                Preference(
                    onClick = {},
                    onLongClick = onLongClick,
                    shapes = betterSegmentedShapes(index = index, count = certificates.size),
                    title = { Text(text = certificateTitle(index, isSystem)) },
                    summary = { Text(text = certificateSummary(certificate)) },
                    modifier = Modifier.animateItem(),
                )
            }
        }

        item(key = "about") {
            PreferenceCategory(
                title = { Text(text = stringResource(R.string.pref_header_about)) },
                modifier = Modifier.animateItem(),
            )
        }

        item(key = "version") {
            Preference(
                onClick = onSourceRepoOpen,
                onLongClick = { onDebugModeChange(!isDebugMode) },
                shapes = BetterSegmentedShapes.single(),
                title = { Text(text = stringResource(R.string.pref_version_name)) },
                summary = { Text(text = versionSummary(isDebugMode)) },
                modifier = Modifier.animateItem(),
            )
        }

        if (isDebugMode) {
            item(key = "debug") {
                PreferenceCategory(
                    title = { Text(text = stringResource(R.string.pref_header_debug)) },
                    modifier = Modifier.animateItem(),
                )
            }

            item(key = "open_log_dir") {
                Preference(
                    onClick = onOpenLogDir,
                    shapes = BetterSegmentedShapes.top(),
                    title = { Text(text = stringResource(R.string.pref_open_log_dir_name)) },
                    summary = { Text(text = stringResource(R.string.pref_open_log_dir_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }

            item(key = "allow_reinstall") {
                SwitchPreference(
                    checked = allowReinstall,
                    onCheckedChange = onAllowReinstallChange,
                    shapes = BetterSegmentedShapes.middle(),
                    title = { Text(text = stringResource(R.string.pref_allow_reinstall_name)) },
                    summary = { Text(text = stringResource(R.string.pref_allow_reinstall_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }

            item(key = "revert_completed") {
                Preference(
                    onClick = onRevertCompleted,
                    shapes = BetterSegmentedShapes.middle(),
                    title = { Text(text = stringResource(R.string.pref_revert_completed_name)) },
                    summary = { Text(text = stringResource(R.string.pref_revert_completed_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }

            item(key = "install_csig_cert") {
                Preference(
                    onClick = onCsigCertInstall,
                    shapes = BetterSegmentedShapes.middle(),
                    title = { Text(text = stringResource(R.string.pref_install_csig_cert_name)) },
                    summary = { Text(text = stringResource(R.string.pref_install_csig_cert_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }

            item(key = "pin_network_id") {
                SwitchPreference(
                    checked = pinNetworkId,
                    onCheckedChange = onPinNetworkIdChange,
                    shapes = BetterSegmentedShapes.bottom(),
                    title = { Text(text = stringResource(R.string.pref_pin_network_id_name)) },
                    summary = { Text(text = stringResource(R.string.pref_pin_network_id_desc)) },
                    modifier = Modifier.animateItem(),
                )
            }
        }
    }

    if (showOtaSourceDialog) {
        OtaSourceDialog(
            initialUri = otaSource,
            onSelect = { uri ->
                onOtaSourceChange(uri)
                showOtaSourceDialog = false
            },
            onDismiss = {
                showOtaSourceDialog = false
            },
        )
    }
}

@Composable
private fun otaSourceSummary(otaSource: Uri?) = otaSource?.formattedString
    ?: stringResource(R.string.pref_ota_source_none)

@Composable
private fun bootloaderStatusSummary(status: SettingsViewModel.BootloaderStatus) = buildString {
    when (status) {
        is SettingsViewModel.BootloaderStatus.Success -> {
            if (status.unlocked) {
                append(stringResource(R.string.pref_bootloader_status_unlocked))
            } else {
                append(stringResource(R.string.pref_bootloader_status_locked))
            }
            append('\n')
            if (status.allowedByCarrier) {
                append(stringResource(R.string.pref_bootloader_status_oemlock_carrier_allowed))
            } else {
                append(stringResource(R.string.pref_bootloader_status_oemlock_carrier_blocked))
            }
            append('\n')
            if (status.allowedByUser) {
                append(stringResource(R.string.pref_bootloader_status_oemlock_user_allowed))
            } else {
                append(stringResource(R.string.pref_bootloader_status_oemlock_user_blocked))
            }
        }
        is SettingsViewModel.BootloaderStatus.Failure -> {
            append(stringResource(R.string.pref_bootloader_status_unknown))
            append('\n')
            append(status.errorMsg)
        }
    }
}

@Composable
private fun certificateTitle(index: Int, isSystem: Boolean): String {
    val validates = if (isSystem) { "OTA + csig" } else { "csig" }

    return stringResource(R.string.pref_certificate_name, (index + 1).toString(), validates)
}

@Composable
private fun certificateSummary(certificate: X509Certificate) = buildString {
    append(stringResource(R.string.pref_certificate_desc_subject,
        certificate.subjectDN.toString()))
    append('\n')

    append(stringResource(R.string.pref_certificate_desc_serial,
        certificate.serialNumber.toString(16)))
    append('\n')

    append(stringResource(R.string.pref_certificate_desc_type, certificate.typeName))
}

@Composable
private fun versionSummary(isDebugMode: Boolean): String {
    val suffix = if (isDebugMode) "+debugmode" else ""

    return "${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_TYPE}${suffix})"
}

@Preview(
    name = "Light Mode",
    showBackground = true,
)
@Preview(
    name = "Dark Mode",
    uiMode = Configuration.UI_MODE_NIGHT_YES,
    showBackground = true,
)
@Composable
private fun PreviewSettingsScreen() {
    val uri = DocumentsContract.buildTreeDocumentUri(EXTERNAL_STORAGE_AUTHORITY, "primary:OTA")

    AppTheme {
        AppScreen(
            title = { Text(text = stringResource(R.string.app_name)) },
        ) { params ->
            SettingsContent(
                otaSource = uri,
                automaticCheck = true,
                automaticInstall = false,
                requireUnmetered = true,
                requireBatteryNotLow = true,
                skipPostInstall = false,
                localNetworkGranted = false,
                androidVersion = "16",
                securityPatchLevel = "2026-05-05",
                fingerprint = Build.FINGERPRINT,
                vbmetaDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                bootSlot = "A",
                bootloaderStatus = SettingsViewModel.BootloaderStatus.Success(
                    unlocked = false,
                    allowedByCarrier = true,
                    allowedByUser = true,
                ),
                certificates = emptyList(),
                isDebugMode = true,
                allowReinstall = false,
                pinNetworkId = true,
                onCheckForUpdates = {},
                onOtaSourceChange = {},
                onOtaSourceReset = {},
                onAutomaticCheckChange = {},
                onAutomaticInstallChange = {},
                onRequireUnmeteredChange = {},
                onRequireBatteryNotLowChange = {},
                onSkipPostInstallChange = {},
                onLocalNetworkGrant = {},
                onCsigCertRemove = {},
                onSourceRepoOpen = {},
                onDebugModeChange = {},
                onOpenLogDir = {},
                onAllowReinstallChange = {},
                onRevertCompleted = {},
                onCsigCertInstall = {},
                onPinNetworkIdChange = {},
                contentPadding = params.contentPadding,
            )
        }
    }
}
