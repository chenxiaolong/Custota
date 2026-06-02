/*
 * SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.settings

import android.content.ContentResolver
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.core.net.toUri
import com.chiller3.custota.R
import com.chiller3.custota.extension.formattedString
import java.net.MalformedURLException
import java.net.URL

@Composable
fun OtaSourceDialog(
    initialUri: Uri?,
    onSelect: (Uri) -> Unit,
    onDismiss: () -> Unit,
) {
    var isLocal by rememberSaveable {
        mutableStateOf(initialUri?.scheme == ContentResolver.SCHEME_CONTENT)
    }
    var uriLocal by rememberSaveable {
        mutableStateOf(if (isLocal) initialUri else null)
    }

    val initialText = remember { if (isLocal) "" else initialUri?.toString() ?: "" }
    val input = rememberTextFieldState(initialText = initialText)
    val uriRemote = tryParseInput(input.text.toString())

    val requestSafDirectory = rememberLauncherForActivityResult(OpenPersistentDocumentTree()) { uri ->
        uri?.let {
            uriLocal = it
        }
    }

    AlertDialog(
        title = { Text(text = stringResource(R.string.dialog_ota_source_title)) },
        text = {
            Column(modifier = Modifier.verticalScroll(state = rememberScrollState())) {
                Text(text = buildMessage(isLocal))

                if (isLocal) {
                    OutlinedButton(
                        onClick = { requestSafDirectory.launch(null) },
                        modifier = Modifier
                            .padding(top = 8.dp)
                            .align(alignment = Alignment.CenterHorizontally),
                    ) {
                        Text(text = changeDirectoryText(uriLocal))
                    }
                } else {
                    OutlinedTextField(
                        state = input,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        placeholder = {
                            Text(text = stringResource(R.string.dialog_ota_source_server_url_hint))
                        },
                        isError = uriRemote is URLParse.Error,
                        supportingText = {
                            if (uriRemote is URLParse.Error && uriRemote.message != null) {
                                Text(text = uriRemote.message)
                            }
                        },
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            keyboardType = KeyboardType.Uri,
                            autoCorrectEnabled = false,
                        ),
                        lineLimits = TextFieldLineLimits.SingleLine,
                    )
                }
            }
        },
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(
                onClick = {
                    if (isLocal) {
                        onSelect(uriLocal!!)
                    } else {
                        onSelect((uriRemote as URLParse.Value).uri)
                    }
                },
                enabled = if (isLocal) {
                    uriLocal != null
                } else {
                    uriRemote is URLParse.Value
                },
            ) {
                Text(text = stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(text = stringResource(android.R.string.cancel))
            }

            TextButton(onClick = { isLocal = !isLocal }) {
                Text(text = switchButtonText(isLocal))
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
        ),
    )
}

@Composable
private fun switchButtonText(isLocal: Boolean) = if (isLocal) {
    stringResource(R.string.dialog_ota_source_use_server_url)
} else {
    stringResource(R.string.dialog_ota_source_use_local_path)
}

@Composable
private fun buildMessage(isLocal: Boolean) = if (isLocal) {
    stringResource(R.string.dialog_ota_source_local_path_message)
} else {
    stringResource(R.string.dialog_ota_source_server_url_message)
}

@Composable
private fun changeDirectoryText(uriLocal: Uri?) = uriLocal?.formattedString
    ?: stringResource(R.string.dialog_ota_source_local_path_select_directory)

private sealed interface URLParse {
    data class Value(val uri: Uri) : URLParse

    data class Error(val message: String?) : URLParse
}

@Composable
private fun tryParseInput(input: String): URLParse {
    if (input.isEmpty()) {
        return URLParse.Error(null)
    }

    val uri = try {
        // The URL round trip is used for validation because Uri allows any input.
        URL(input).toString().toUri()
    } catch (_: MalformedURLException) {
        return URLParse.Error(stringResource(R.string.dialog_ota_source_server_url_error_malformed))
    }

    return if (uri.scheme == "http" || uri.scheme == "https") {
        URLParse.Value(uri)
    } else {
        URLParse.Error(stringResource(R.string.dialog_ota_source_server_url_error_bad_protocol))
    }
}
