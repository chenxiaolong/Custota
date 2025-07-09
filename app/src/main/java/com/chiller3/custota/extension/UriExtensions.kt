/*
 * SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota.extension

import android.content.ContentResolver
import android.net.Uri

private const val EXTERNAL_STORAGE_AUTHORITY = "com.android.externalstorage.documents"

private val LOCAL_PROVIDERS = arrayOf(
    EXTERNAL_STORAGE_AUTHORITY,
    "com.android.providers.downloads.documents",
    "com.android.providers.media.documents",
)

val Uri.formattedString: String
    get() = when (scheme) {
        ContentResolver.SCHEME_FILE -> path!!
        ContentResolver.SCHEME_CONTENT -> {
            val prefix = when (authority) {
                EXTERNAL_STORAGE_AUTHORITY -> ""
                // Include the authority to reduce ambiguity when this isn't a SAF URI provided by
                // Android's local filesystem document provider
                else -> "[$authority] "
            }
            val segments = pathSegments

            // If this looks like a SAF tree/document URI, then try and show the document ID. This
            // cannot be implemented in a way that prevents all false positives.
            if (segments.size == 4 && segments[0] == "tree" && segments[2] == "document") {
                prefix + segments[3]
            } else if (segments.size == 2 && segments[0] == "tree") {
                prefix + segments[1]
            } else {
                toString()
            }
        }
        else -> toString()
    }

val Uri.isGuaranteedLocalFile: Boolean
    get() = (scheme == ContentResolver.SCHEME_CONTENT && LOCAL_PROVIDERS.contains(authority))
            || scheme == ContentResolver.SCHEME_FILE

val Uri.isGuaranteedNetworkUri: Boolean
    get() = scheme != ContentResolver.SCHEME_CONTENT && scheme != ContentResolver.SCHEME_FILE
