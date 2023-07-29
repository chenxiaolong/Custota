/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.wrapper

import android.annotation.SuppressLint

object SystemPropertiesProxy {
    @SuppressLint("PrivateApi")
    private val CLS = Class.forName("android.os.SystemProperties")

    private val METHOD_GET = CLS.getDeclaredMethod("get", String::class.java)

    fun get(key: String): String {
        return METHOD_GET.invoke(null, key) as String
    }
}
