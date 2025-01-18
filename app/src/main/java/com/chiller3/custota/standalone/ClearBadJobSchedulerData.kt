/*
 * SPDX-FileCopyrightText: 2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:Suppress("SameParameterValue")

package com.chiller3.custota.standalone

import android.annotation.SuppressLint
import android.util.Log
import android.util.Xml
import com.chiller3.custota.BuildConfig
import org.xmlpull.v1.XmlPullParser
import java.io.InputStream
import java.lang.invoke.MethodHandles
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteIfExists
import kotlin.io.path.inputStream
import kotlin.io.path.isRegularFile
import kotlin.io.path.walk
import kotlin.system.exitProcess

private val TAG = MethodHandles.lookup().lookupClass().simpleName

private val PACKAGES_FILE = Paths.get("/data/system/packages.xml")
private val JOB_SCHEDULER_DIR = Paths.get("/data/system/job")

private var dryRun = false

private fun delete(path: Path) {
    if (dryRun) {
        Log.i(TAG, "Would have deleted: $path")
    } else {
        Log.i(TAG, "Deleting: $path")
        path.deleteIfExists()
    }
}

@SuppressLint("BlockedPrivateApi")
private fun resolvePullParser(stream: InputStream): XmlPullParser {
    val method = Xml::class.java.getDeclaredMethod("resolvePullParser", InputStream::class.java)
    return method.invoke(null, stream) as XmlPullParser
}

private fun parseJobPackage(parser: XmlPullParser): Pair<String, Int>? {
    val tags = mutableListOf<String>()

    while (true) {
        val token = parser.nextToken()

        when (token) {
            XmlPullParser.START_TAG -> {
                tags.add(parser.name)

                if (tags.size == 2 && tags[0] == "job-info" && tags[1] == "job") {
                    val name = (0 until parser.attributeCount)
                        .find { parser.getAttributeName(it) == "package" }
                        ?.let { parser.getAttributeValue(it) }
                        ?: throw IllegalStateException("<job> has no 'package' attribute")
                    val userId = (0 until parser.attributeCount)
                        .find { parser.getAttributeName(it) == "uid" }
                        ?.let { parser.getAttributeValue(it) }
                        ?: throw IllegalStateException("<job> has no 'uid' attribute")

                    return name to userId.toInt()
                }
            }
            XmlPullParser.END_TAG -> {
                if (tags.removeLastOrNull() == null) {
                    throw IllegalStateException("Tag stack is empty")
                }
            }
            XmlPullParser.END_DOCUMENT -> break
        }
    }

    return null
}

@OptIn(ExperimentalPathApi::class)
private fun clearBadJobSchedulerData(packageName: String, uid: Int?): Boolean {
    var ret = true

    for (path in JOB_SCHEDULER_DIR.walk()) {
        if (!path.isRegularFile()) {
            continue
        }

        val (jobPackageName, jobUid) = try {
            path.inputStream().use { parseJobPackage(resolvePullParser(it)) } ?: continue
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse $path", e)
            ret = false
            continue
        }

        try {
            if (jobPackageName == packageName && jobUid != uid) {
                delete(path)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to delete $path", e)
            ret = false
        }
    }

    return ret
}

private fun parsePackageUid(parser: XmlPullParser, packageName: String): Int? {
    val tags = mutableListOf<String>()

    while (true) {
        val token = parser.nextToken()

        when (token) {
            XmlPullParser.START_TAG -> {
                tags.add(parser.name)

                if (tags.size == 2 && tags[0] == "packages" && tags[1] == "package") {
                    val name = (0 until parser.attributeCount)
                        .find { parser.getAttributeName(it) == "name" }
                        ?.let { parser.getAttributeValue(it) }
                        ?: throw IllegalStateException("<package> has no 'name' attribute")
                    if (name == packageName) {
                        val userId = (0 until parser.attributeCount)
                            .find { parser.getAttributeName(it) == "userId" }
                            ?.let { parser.getAttributeValue(it) }
                            ?: throw IllegalStateException("<package> has no 'userId' attribute")

                        return userId.toInt()
                    }
                }
            }
            XmlPullParser.END_TAG -> {
                if (tags.removeLastOrNull() == null) {
                    throw IllegalStateException("Tag stack is empty")
                }
            }
            XmlPullParser.END_DOCUMENT -> break
        }
    }

    return null
}

private fun getPackageUid(packageName: String): Int? =
    PACKAGES_FILE.inputStream().use { input ->
        parsePackageUid(resolvePullParser(input), packageName)
    }

private fun mainInternal() {
    val expectedUid = getPackageUid(BuildConfig.APPLICATION_ID)
    Log.i(TAG, "Expected UID: $expectedUid")

    clearBadJobSchedulerData(BuildConfig.APPLICATION_ID, expectedUid)
}

fun main(args: Array<String>) {
    if ("--dry-run" in args) {
        dryRun = true
    }

    try {
        mainInternal()
    } catch (e: Exception) {
        Log.e(TAG, "Failed to clear bad JobScheduler data", e)
        exitProcess(1)
    }
}
