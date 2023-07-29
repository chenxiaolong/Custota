/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * This file is part of Custota, based on BCR code.
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

package com.chiller3.custota.wrapper

import android.annotation.SuppressLint
import android.os.IBinder

object ServiceManagerProxy {
    @SuppressLint("PrivateApi")
    private val CLS = Class.forName("android.os.ServiceManager")

    @SuppressLint("SoonBlockedPrivateApi")
    private val METHOD_GET_SERVICE_OR_THROW =
        CLS.getDeclaredMethod("getServiceOrThrow", String::class.java)

    fun getServiceOrThrow(name: String): IBinder {
        return METHOD_GET_SERVICE_OR_THROW.invoke(null, name) as IBinder
    }
}
