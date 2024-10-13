/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

package com.chiller3.custota.extension

import android.content.ContentResolver
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import java.io.IOException

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

private fun <R> DocumentFile.withChildrenWithColumns(
    columns: Array<String>,
    block: (Cursor, Sequence<Pair<DocumentFile, Cursor>>) -> R,
): R {
    require(isTree) { "Not a tree URI" }

    // These reflection calls access private fields, but everything is part of the
    // androidx.documentfile:documentfile dependency and we control the version of that.
    val constructor = javaClass.getDeclaredConstructor(
        DocumentFile::class.java,
        Context::class.java,
        Uri::class.java,
    ).apply {
        isAccessible = true
    }

    val cursor = context!!.contentResolver.query(
        DocumentsContract.buildChildDocumentsUriUsingTree(
            uri,
            DocumentsContract.getDocumentId(uri),
        ),
        columns + arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID),
        null, null, null,
    ) ?: throw IOException("Query returned null cursor: $uri: $columns")

    return cursor.use {
        val indexDocumentId =
            cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)

        block(cursor, cursor.asSequence().map {
            val documentId = it.getString(indexDocumentId)
            val child: DocumentFile = constructor.newInstance(
                this,
                context,
                DocumentsContract.buildDocumentUriUsingTree(uri, documentId),
            )

            Pair(child, it)
        })
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

    return try {
        withChildrenWithColumns(arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME)) { c, sequence ->
            val indexDisplayName =
                c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)

            sequence.find { it.second.getString(indexDisplayName) == displayName }?.first
        }
    } catch (e: Exception) {
        Log.w(TAG, "Failed to query tree URI", e)
        null
    }
}

/** Like [DocumentFile.findFileFast], but accepts nested paths. */
fun DocumentFile.findNestedFile(path: List<String>): DocumentFile? {
    var file = this
    for (segment in path) {
        file = file.findFileFast(segment) ?: return null
    }
    return file
}
