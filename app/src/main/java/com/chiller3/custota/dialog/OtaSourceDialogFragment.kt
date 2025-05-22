/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.dialog

import android.app.Dialog
import android.content.ContentResolver
import android.content.DialogInterface
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.core.view.isVisible
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.databinding.DialogOtaSourceBinding
import com.chiller3.custota.extension.formattedString
import com.chiller3.custota.settings.OpenPersistentDocumentTree
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.net.MalformedURLException
import java.net.URL
import androidx.core.net.toUri

class OtaSourceDialogFragment : DialogFragment() {
    companion object {
        val TAG: String = OtaSourceDialogFragment::class.java.simpleName

        const val RESULT_SUCCESS = "success"
        private const val STATE_IS_LOCAL = "is_local"
        private const val STATE_URI_LOCAL = "uri_local"
    }

    private lateinit var prefs: Preferences
    private lateinit var binding: DialogOtaSourceBinding
    private var uriRemote: Uri? = null
    private var uriLocal: Uri? = null
    private var isLocal = false
    private var success: Boolean = false

    private val requestSafDirectory =
        registerForActivityResult(OpenPersistentDocumentTree()) { uri ->
            uriLocal = uri

            refreshModeState()
            refreshOkButtonEnabledState()
        }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val context = requireContext()
        prefs = Preferences(context)

        binding = DialogOtaSourceBinding.inflate(layoutInflater)

        binding.url.hint = getString(R.string.dialog_ota_source_server_url_hint)
        binding.url.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        binding.url.addTextChangedListener {
            uriRemote = null

            try {
                if (it.isNullOrEmpty()) {
                    // Avoid showing error initially
                    binding.urlLayout.error = null
                    binding.urlLayout.isErrorEnabled = false
                } else {
                    // The URL round trip is used for validation because Uri allows any input
                    val newUri = URL(it.toString()).toString().toUri()

                    if (newUri.scheme == "http" || newUri.scheme == "https") {
                        uriRemote = newUri
                        binding.urlLayout.error = null
                        // Don't keep the layout space for the error message reserved
                        binding.urlLayout.isErrorEnabled = false
                    } else {
                        binding.urlLayout.error =
                            getString(R.string.dialog_ota_source_server_url_error_bad_protocol)
                    }
                }
            } catch (e: MalformedURLException) {
                binding.urlLayout.error =
                    getString(R.string.dialog_ota_source_server_url_error_malformed)
            }

            refreshModeState()
            refreshOkButtonEnabledState()
        }

        binding.changeDirectory.setOnClickListener {
            requestSafDirectory.launch(null)
        }

        if (savedInstanceState == null) {
            val oldUri = prefs.otaSource

            isLocal = oldUri?.scheme == ContentResolver.SCHEME_CONTENT

            if (isLocal) {
                uriLocal = oldUri
            } else {
                // The text change listener will set uriRemote
                binding.url.setText(oldUri?.toString())
            }
        } else {
            isLocal = savedInstanceState.getBoolean(STATE_IS_LOCAL)
            uriLocal = savedInstanceState.getParcelable(STATE_URI_LOCAL, Uri::class.java)
        }

        return MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_ota_source_title)
            .setView(binding.root)
            .setPositiveButton(R.string.dialog_action_ok) { _, _ ->
                val uri = if (isLocal) { uriLocal } else { uriRemote }
                prefs.otaSource = uri
                success = true
            }
            .setNegativeButton(R.string.dialog_action_cancel, null)
            .setNeutralButton("<dummy>", null)
            .create()
            .apply {
                setCanceledOnTouchOutside(false)
            }
    }

    override fun onStart() {
        super.onStart()

        // This is set separately to prevent the builtin dismiss callback from being called
        (dialog as AlertDialog?)!!.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            isLocal = !isLocal
            refreshModeState()
            refreshOkButtonEnabledState()
        }

        refreshModeState()
        refreshOkButtonEnabledState()
    }

    override fun onDismiss(dialog: DialogInterface) {
        super.onDismiss(dialog)

        setFragmentResult(tag!!, bundleOf(RESULT_SUCCESS to success))
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_IS_LOCAL, isLocal)
        outState.putParcelable(STATE_URI_LOCAL, uriLocal)
    }

    private fun refreshModeState() {
        (dialog as AlertDialog?)?.getButton(AlertDialog.BUTTON_NEUTRAL)?.text = if (isLocal) {
            getString(R.string.dialog_ota_source_use_server_url)
        } else {
            getString(R.string.dialog_ota_source_use_local_path)
        }

        binding.message.setText(if (isLocal) {
            R.string.dialog_ota_source_local_path_message
        } else {
            R.string.dialog_ota_source_server_url_message
        })

        binding.urlLayout.isVisible = !isLocal
        binding.changeDirectory.isVisible = isLocal
        if (uriLocal != null) {
            binding.changeDirectory.text = uriLocal?.formattedString
        } else {
            binding.changeDirectory.setText(R.string.dialog_ota_source_local_path_select_directory)
        }
    }

    private fun refreshOkButtonEnabledState() {
        val uri = if (isLocal) { uriLocal } else { uriRemote }

        (dialog as AlertDialog?)?.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = uri != null
    }
}
