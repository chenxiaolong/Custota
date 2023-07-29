/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.settings

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.chiller3.custota.updater.OtaPaths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

class SettingsViewModel : ViewModel() {
    private val _certs = MutableStateFlow<List<X509Certificate>>(emptyList())
    val certs: StateFlow<List<X509Certificate>> = _certs

    init {
        loadCertificates()
    }

    private fun loadCertificates() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                val result = mutableListOf<X509Certificate>()

                try {
                    val factory = CertificateFactory.getInstance("X.509")

                    ZipFile(OtaPaths.OTACERTS_ZIP).use { zip ->
                        for (entry in zip.entries()) {
                            if (!entry.name.endsWith(".x509.pem")) {
                                Log.d(TAG, "Skipping ${entry.name}")
                                continue
                            }

                            zip.getInputStream(entry).use { stream ->
                                result.add(factory.generateCertificate(stream) as X509Certificate)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to load certificates")
                }

                _certs.update { result }
            }
        }
    }

    companion object {
        private val TAG = SettingsViewModel::class.java.simpleName
    }
}