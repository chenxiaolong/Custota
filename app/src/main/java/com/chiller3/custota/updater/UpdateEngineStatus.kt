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

package com.chiller3.custota.updater

/** Must match AOSP's system/update_engine/common/error_code.h. */
@Suppress("MemberVisibilityCanBePrivate")
object UpdateEngineStatus {
    const val IDLE = 0
    const val CHECKING_FOR_UPDATE = 1
    const val UPDATE_AVAILABLE = 2
    const val DOWNLOADING = 3
    const val VERIFYING = 4
    const val FINALIZING = 5
    const val UPDATED_NEED_REBOOT = 6
    const val REPORTING_ERROR_EVENT = 7
    const val ATTEMPTING_ROLLBACK = 8
    const val DISABLED = 9

    private val STRINGS = arrayOf(
        UpdateEngineStatus::IDLE.name,
        UpdateEngineStatus::CHECKING_FOR_UPDATE.name,
        UpdateEngineStatus::UPDATE_AVAILABLE.name,
        UpdateEngineStatus::DOWNLOADING.name,
        UpdateEngineStatus::VERIFYING.name,
        UpdateEngineStatus::FINALIZING.name,
        UpdateEngineStatus::UPDATED_NEED_REBOOT.name,
        UpdateEngineStatus::REPORTING_ERROR_EVENT.name,
        UpdateEngineStatus::ATTEMPTING_ROLLBACK.name,
        UpdateEngineStatus::DISABLED.name,
    )

    init {
        assert(STRINGS.size == DISABLED + 1)
    }

    @JvmStatic
    fun toString(status: Int): String {
        val text = if (status in STRINGS.indices) {
            STRINGS[status]
        } else {
            "<unknown>"
        }

        return "$status/$text"
    }
}
