/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota.extension

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.documentfile.provider.DocumentFile

private const val TAG = "DocumentFileExtensions"

/** Get the internal [Context] for a DocumentsProvider-backed file. */
private val DocumentFile.context: Context?
    get() = when (uri.scheme) {
        ContentResolver.SCHEME_CONTENT -> {
            javaClass.getDeclaredField("mContext").apply {
                isAccessible = true
            }.get(this) as Context
        }
        else -> null
    }

private val DocumentFile.isTree: Boolean
    get() = uri.scheme == ContentResolver.SCHEME_CONTENT && DocumentsContract.isTreeUri(uri)

private fun DocumentFile.iterChildrenWithColumns(extraColumns: Array<String>) = iterator {
    require(isTree) { "Not a tree URI" }

    val file = this@iterChildrenWithColumns

    // These reflection calls access private fields, but everything is part of the
    // androidx.documentfile:documentfile dependency and we control the version of that.
    val constructor = file.javaClass.getDeclaredConstructor(
        DocumentFile::class.java,
        Context::class.java,
        Uri::class.java,
    ).apply {
        isAccessible = true
    }

    context!!.contentResolver.query(
        DocumentsContract.buildChildDocumentsUriUsingTree(
            uri,
            DocumentsContract.getDocumentId(uri),
        ),
        arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID) + extraColumns,
        null, null, null,
    )?.use {
        while (it.moveToNext()) {
            val child: DocumentFile = constructor.newInstance(
                file,
                context,
                DocumentsContract.buildDocumentUriUsingTree(uri, it.getString(0)),
            )

            yield(Pair(child, it))
        }
    }
}

/**
 * Like [DocumentFile.findFile], but faster for tree URIs.
 *
 * [DocumentFile.findFile] performs a query for the document ID list and then performs separate
 * queries for each document to get the name. This is extremely slow on some devices and is
 * unnecessary because [DocumentsContract.Document.COLUMN_DOCUMENT_ID] and
 * [DocumentsContract.Document.COLUMN_DISPLAY_NAME] can be queried at the same time.
 */
fun DocumentFile.findFileFast(displayName: String): DocumentFile? {
    if (!isTree) {
        return findFile(displayName)
    }

    try {
        return iterChildrenWithColumns(arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME))
            .asSequence()
            .find { it.second.getString(1) == displayName }
            ?.first
    } catch (e: Exception) {
        Log.w(TAG, "Failed to query tree URI", e)
    }

    return null
}

/** Like [DocumentFile.findFileFast], but accepts nested paths. */
fun DocumentFile.findNestedFile(path: List<String>): DocumentFile? {
    var file = this
    for (segment in path) {
        file = file.findFileFast(segment) ?: return null
    }
    return file
}
