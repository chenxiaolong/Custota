/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.InputStream
import java.lang.Long.min

/**
 * Present a view of a file offset range as an input stream.
 *
 * This will seek to the specified offset and takes ownership of the file descriptor.
 */
class PartialFdInputStream(
    private val pfd: ParcelFileDescriptor,
    offset: Long,
    private val size: Long,
) : InputStream() {
    private var pos = 0L

    init {
        Os.lseek(pfd.fileDescriptor, offset, OsConstants.SEEK_SET)
    }

    override fun close() {
        pfd.close()
    }

    override fun read(): Int {
        val buf = ByteArray(1)
        if (read(buf, 0, 1) != 1) {
            return -1
        }

        return buf[0].toInt()
    }

    override fun read(b: ByteArray?, off: Int, len: Int): Int {
        val toRead = min(len.toLong(), size - pos).toInt()
        val n = Os.read(pfd.fileDescriptor, b, off, toRead)
        pos += n
        return n
    }
}