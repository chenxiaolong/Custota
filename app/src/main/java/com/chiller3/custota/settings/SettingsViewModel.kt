/*
 * SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.settings

import android.app.Application
import android.net.Uri
import android.service.oemlock.IOemLockService
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.chiller3.custota.Preferences
import com.chiller3.custota.extension.toSingleLineString
import com.chiller3.custota.updater.OtaPaths
import com.chiller3.custota.wrapper.ServiceManagerProxy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

sealed interface Alert {
    data class SystemCertLoadFailure(val error: String) : Alert

    data class CsigCertLoadFailure(val error: String) : Alert

    data object BrowserNotFound : Alert

    data object DocumentsUINotFound : Alert
}

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = Preferences(getApplication())

    private val _alerts = MutableStateFlow<List<Alert>>(emptyList())
    val alerts = _alerts.asStateFlow()

    private val _certificates = MutableStateFlow<List<Pair<X509Certificate, Boolean>>>(emptyList())
    val certificates = _certificates.asStateFlow()

    private val _bootloaderStatus = MutableStateFlow<BootloaderStatus?>(null)
    val bootloaderStatus = _bootloaderStatus.asStateFlow()

    init {
        loadCerts()
    }

    fun acknowledgeFirstAlert() {
        _alerts.update { it.drop(1) }
    }

    fun addAlert(alert: Alert) {
        _alerts.update { it + alert }
    }

    private fun loadCerts() {
        viewModelScope.launch {
            val systemCerts = try {
                withContext(Dispatchers.IO) {
                    OtaPaths.otaCerts
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load system certificates", e)
                _alerts.update { it + Alert.SystemCertLoadFailure(e.toSingleLineString()) }
                emptySet()
            }

            val csigCerts = try {
                // Avoid duplicates.
                prefs.csigCerts.subtract(systemCerts)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load user csig certificates", e)
                _alerts.update { it + Alert.CsigCertLoadFailure(e.toSingleLineString()) }
                emptySet()
            }

            _certificates.update { systemCerts.sortedWith(certCompare).map { it to true } +
                    csigCerts.sortedWith(certCompare).map { it to false } }
        }
    }

    fun installCsigCert(uri: Uri) {
        viewModelScope.launch {
            val cert = try {
                withContext(Dispatchers.IO) {
                    val factory = CertificateFactory.getInstance("X.509")

                    getApplication<Application>().contentResolver.openInputStream(uri)?.use {
                        factory.generateCertificate(it) as X509Certificate
                    } ?: throw IOException("Null input stream: $uri")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load certificate: $uri", e)
                _alerts.update { it + Alert.CsigCertLoadFailure(e.toSingleLineString()) }
                return@launch
            }

            val allCerts = _certificates.value

            if (allCerts.any { it.first == cert }) {
                Log.w(TAG, "Certificate already exists: $cert")
                return@launch
            }

            Log.d(TAG, "Installing user csig certificate: $cert")

            prefs.csigCerts = sequence {
                yieldAll(allCerts.asSequence().filter { !it.second }.map { it.first })
                yield(cert)
            }.toSet()

            loadCerts()
        }
    }

    fun removeCsigCert(certificate: X509Certificate) {
        Log.d(TAG, "Removing user csig certificate: $certificate")

        prefs.csigCerts = _certificates
            .value
            .asSequence()
            .filter { it.first != certificate }
            .map { it.first }
            .toSet()

        loadCerts()
    }

    fun refreshBootloaderStatus() {
        val status = try {
            val service = IOemLockService.Stub.asInterface(
                ServiceManagerProxy.getServiceOrThrow("oem_lock"))

            BootloaderStatus.Success(
                service.isDeviceOemUnlocked,
                service.isOemUnlockAllowedByCarrier,
                service.isOemUnlockAllowedByUser,
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query bootloader status", e)
            BootloaderStatus.Failure(e.toSingleLineString())
        }

        _bootloaderStatus.update { status }
    }

    sealed interface BootloaderStatus {
        data class Success(
            val unlocked: Boolean,
            val allowedByCarrier: Boolean,
            val allowedByUser: Boolean,
        ) : BootloaderStatus

        data class Failure(val errorMsg: String) : BootloaderStatus
    }

    companion object {
        private val TAG = SettingsViewModel::class.java.simpleName

        private val certCompare = compareBy<X509Certificate>(
            { it.subjectDN.name },
            { it.serialNumber },
        )
    }
}