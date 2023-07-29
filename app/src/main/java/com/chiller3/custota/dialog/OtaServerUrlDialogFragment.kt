/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * This file is part of Custota.
 *
 * Custota is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * Custota is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Custota.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.chiller3.custota.dialog

import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.text.InputType
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.databinding.DialogTextInputBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.net.MalformedURLException
import java.net.URL

class OtaServerUrlDialogFragment : DialogFragment() {
    companion object {
        val TAG: String = OtaServerUrlDialogFragment::class.java.simpleName

        const val RESULT_SUCCESS = "success"
    }

    private lateinit var prefs: Preferences
    private lateinit var binding: DialogTextInputBinding
    private var url: URL? = null
    // Allow the user to clear the URL
    private var isEmpty = false
    private var success: Boolean = false

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val context = requireContext()
        prefs = Preferences(context)

        binding = DialogTextInputBinding.inflate(layoutInflater)

        binding.message.setText(R.string.dialog_ota_server_url_message)

        binding.text.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        binding.text.addTextChangedListener {
            url = null

            try {
                if (it.isNullOrEmpty()) {
                    isEmpty = true
                } else {
                    isEmpty = false

                    val newUrl = URL(it.toString())
                    if (newUrl.protocol == "http" || newUrl.protocol == "https") {
                        url = newUrl
                        binding.textLayout.error = null
                        // Don't keep the layout space for the error message reserved
                        binding.textLayout.isErrorEnabled = false
                    } else {
                        binding.textLayout.error = getString(
                            R.string.dialog_ota_server_url_error_bad_protocol)
                    }
                }
            } catch (e: MalformedURLException) {
                binding.textLayout.error = getString(R.string.dialog_ota_server_url_error_malformed)
            }

            refreshOkButtonEnabledState()
        }
        if (savedInstanceState == null) {
            val oldUrl = prefs.otaServerUrl?.toString()
            binding.text.setText(oldUrl)
            isEmpty = oldUrl == null
        }

        return MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_ota_server_url_title)
            .setView(binding.root)
            .setPositiveButton(R.string.dialog_action_ok) { _, _ ->
                prefs.otaServerUrl = url
                success = true
            }
            .setNegativeButton(R.string.dialog_action_cancel, null)
            .create()
            .apply {
                setCanceledOnTouchOutside(false)
            }
    }

    override fun onStart() {
        super.onStart()
        refreshOkButtonEnabledState()
    }

    override fun onDismiss(dialog: DialogInterface) {
        super.onDismiss(dialog)

        setFragmentResult(tag!!, bundleOf(RESULT_SUCCESS to success))
    }

    private fun refreshOkButtonEnabledState() {
        (dialog as AlertDialog?)?.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled =
            isEmpty || url != null
    }
}
