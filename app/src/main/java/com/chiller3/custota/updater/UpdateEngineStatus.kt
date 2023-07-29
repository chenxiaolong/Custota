/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
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
