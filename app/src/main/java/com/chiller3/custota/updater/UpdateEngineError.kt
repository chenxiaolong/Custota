/*
 * SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

/** Must match AOSP's system/update_engine/common/error_code.h. */
@Suppress("MemberVisibilityCanBePrivate")
object UpdateEngineError {
    const val SUCCESS = 0
    const val ERROR = 1
    const val OMAHA_REQUEST_ERROR = 2
    const val OMAHA_RESPONSE_HANDLER_ERROR = 3
    const val FILESYSTEM_COPIER_ERROR = 4
    const val POSTINSTALL_RUNNER_ERROR = 5
    const val PAYLOAD_MISMATCHED_TYPE = 6
    const val INSTALL_DEVICE_OPEN_ERROR = 7
    const val KERNEL_DEVICE_OPEN_ERROR = 8
    const val DOWNLOAD_TRANSFER_ERROR = 9
    const val PAYLOAD_HASH_MISMATCH_ERROR = 10
    const val PAYLOAD_SIZE_MISMATCH_ERROR = 11
    const val DOWNLOAD_PAYLOAD_VERIFICATION_ERROR = 12
    const val DOWNLOAD_NEW_PARTITION_INFO_ERROR = 13
    const val DOWNLOAD_WRITE_ERROR = 14
    const val NEW_ROOTFS_VERIFICATION_ERROR = 15
    const val NEW_KERNEL_VERIFICATION_ERROR = 16
    const val SIGNED_DELTA_PAYLOAD_EXPECTED_ERROR = 17
    const val DOWNLOAD_PAYLOAD_PUB_KEY_VERIFICATION_ERROR = 18
    const val POSTINSTALL_BOOTED_FROM_FIRMWARE_B = 19
    const val DOWNLOAD_STATE_INITIALIZATION_ERROR = 20
    const val DOWNLOAD_INVALID_METADATA_MAGIC_STRING = 21
    const val DOWNLOAD_SIGNATURE_MISSING_IN_MANIFEST = 22
    const val DOWNLOAD_MANIFEST_PARSE_ERROR = 23
    const val DOWNLOAD_METADATA_SIGNATURE_ERROR = 24
    const val DOWNLOAD_METADATA_SIGNATURE_VERIFICATION_ERROR = 25
    const val DOWNLOAD_METADATA_SIGNATURE_MISMATCH = 26
    const val DOWNLOAD_OPERATION_HASH_VERIFICATION_ERROR = 27
    const val DOWNLOAD_OPERATION_EXECUTION_ERROR = 28
    const val DOWNLOAD_OPERATION_HASH_MISMATCH = 29
    const val OMAHA_REQUEST_EMPTY_RESPONSE_ERROR = 30
    const val OMAHA_REQUEST_XML_PARSE_ERROR = 31
    const val DOWNLOAD_INVALID_METADATA_SIZE = 32
    const val DOWNLOAD_INVALID_METADATA_SIGNATURE = 33
    const val OMAHA_RESPONSE_INVALID = 34
    const val OMAHA_UPDATE_IGNORED_PER_POLICY = 35
    const val OMAHA_UPDATE_DEFERRED_PER_POLICY = 36
    const val OMAHA_ERROR_IN_HTTP_RESPONSE = 37
    const val DOWNLOAD_OPERATION_HASH_MISSING_ERROR = 38
    const val DOWNLOAD_METADATA_SIGNATURE_MISSING_ERROR = 39
    const val OMAHA_UPDATE_DEFERRED_FOR_BACKOFF = 40
    const val POSTINSTALL_POWERWASH_ERROR = 41
    const val UPDATE_CANCELED_BY_CHANNEL_CHANGE = 42
    const val POSTINSTALL_FIRMWARE_RO_NOT_UPDATABLE = 43
    const val UNSUPPORTED_MAJOR_PAYLOAD_VERSION = 44
    const val UNSUPPORTED_MINOR_PAYLOAD_VERSION = 45
    const val OMAHA_REQUEST_XML_HAS_ENTITY_DECL = 46
    const val FILESYSTEM_VERIFIER_ERROR = 47
    const val USER_CANCELED = 48
    const val NON_CRITICAL_UPDATE_IN_OOBE = 49
    const val OMAHA_UPDATE_IGNORED_OVER_CELLULAR = 50
    const val PAYLOAD_TIMESTAMP_ERROR = 51
    const val UPDATED_BUT_NOT_ACTIVE = 52
    const val NO_UPDATE = 53
    const val ROLLBACK_NOT_POSSIBLE = 54
    const val FIRST_ACTIVE_OMAHA_PING_SENT_PERSISTENCE_ERROR = 55
    const val VERITY_CALCULATION_ERROR = 56
    const val INTERNAL_LIB_CURL_ERROR = 57
    const val UNRESOLVED_HOST_ERROR = 58
    const val UNRESOLVED_HOST_RECOVERED = 59
    const val NOT_ENOUGH_SPACE = 60
    const val DEVICE_CORRUPTED = 61
    const val PACKAGE_EXCLUDED_FROM_UPDATE = 62
    const val POST_INSTALL_MOUNT_ERROR = 63
    const val OVERLAYFS_ENABLED_ERROR = 64
    const val UPDATE_PROCESSING = 65
    const val UPDATE_ALREADY_INSTALLED = 66

    private val STRINGS = arrayOf(
        UpdateEngineError::SUCCESS.name,
        UpdateEngineError::ERROR.name,
        UpdateEngineError::OMAHA_REQUEST_ERROR.name,
        UpdateEngineError::OMAHA_RESPONSE_HANDLER_ERROR.name,
        UpdateEngineError::FILESYSTEM_COPIER_ERROR.name,
        UpdateEngineError::POSTINSTALL_RUNNER_ERROR.name,
        UpdateEngineError::PAYLOAD_MISMATCHED_TYPE.name,
        UpdateEngineError::INSTALL_DEVICE_OPEN_ERROR.name,
        UpdateEngineError::KERNEL_DEVICE_OPEN_ERROR.name,
        UpdateEngineError::DOWNLOAD_TRANSFER_ERROR.name,
        UpdateEngineError::PAYLOAD_HASH_MISMATCH_ERROR.name,
        UpdateEngineError::PAYLOAD_SIZE_MISMATCH_ERROR.name,
        UpdateEngineError::DOWNLOAD_PAYLOAD_VERIFICATION_ERROR.name,
        UpdateEngineError::DOWNLOAD_NEW_PARTITION_INFO_ERROR.name,
        UpdateEngineError::DOWNLOAD_WRITE_ERROR.name,
        UpdateEngineError::NEW_ROOTFS_VERIFICATION_ERROR.name,
        UpdateEngineError::NEW_KERNEL_VERIFICATION_ERROR.name,
        UpdateEngineError::SIGNED_DELTA_PAYLOAD_EXPECTED_ERROR.name,
        UpdateEngineError::DOWNLOAD_PAYLOAD_PUB_KEY_VERIFICATION_ERROR.name,
        UpdateEngineError::POSTINSTALL_BOOTED_FROM_FIRMWARE_B.name,
        UpdateEngineError::DOWNLOAD_STATE_INITIALIZATION_ERROR.name,
        UpdateEngineError::DOWNLOAD_INVALID_METADATA_MAGIC_STRING.name,
        UpdateEngineError::DOWNLOAD_SIGNATURE_MISSING_IN_MANIFEST.name,
        UpdateEngineError::DOWNLOAD_MANIFEST_PARSE_ERROR.name,
        UpdateEngineError::DOWNLOAD_METADATA_SIGNATURE_ERROR.name,
        UpdateEngineError::DOWNLOAD_METADATA_SIGNATURE_VERIFICATION_ERROR.name,
        UpdateEngineError::DOWNLOAD_METADATA_SIGNATURE_MISMATCH.name,
        UpdateEngineError::DOWNLOAD_OPERATION_HASH_VERIFICATION_ERROR.name,
        UpdateEngineError::DOWNLOAD_OPERATION_EXECUTION_ERROR.name,
        UpdateEngineError::DOWNLOAD_OPERATION_HASH_MISMATCH.name,
        UpdateEngineError::OMAHA_REQUEST_EMPTY_RESPONSE_ERROR.name,
        UpdateEngineError::OMAHA_REQUEST_XML_PARSE_ERROR.name,
        UpdateEngineError::DOWNLOAD_INVALID_METADATA_SIZE.name,
        UpdateEngineError::DOWNLOAD_INVALID_METADATA_SIGNATURE.name,
        UpdateEngineError::OMAHA_RESPONSE_INVALID.name,
        UpdateEngineError::OMAHA_UPDATE_IGNORED_PER_POLICY.name,
        UpdateEngineError::OMAHA_UPDATE_DEFERRED_PER_POLICY.name,
        UpdateEngineError::OMAHA_ERROR_IN_HTTP_RESPONSE.name,
        UpdateEngineError::DOWNLOAD_OPERATION_HASH_MISSING_ERROR.name,
        UpdateEngineError::DOWNLOAD_METADATA_SIGNATURE_MISSING_ERROR.name,
        UpdateEngineError::OMAHA_UPDATE_DEFERRED_FOR_BACKOFF.name,
        UpdateEngineError::POSTINSTALL_POWERWASH_ERROR.name,
        UpdateEngineError::UPDATE_CANCELED_BY_CHANNEL_CHANGE.name,
        UpdateEngineError::POSTINSTALL_FIRMWARE_RO_NOT_UPDATABLE.name,
        UpdateEngineError::UNSUPPORTED_MAJOR_PAYLOAD_VERSION.name,
        UpdateEngineError::UNSUPPORTED_MINOR_PAYLOAD_VERSION.name,
        UpdateEngineError::OMAHA_REQUEST_XML_HAS_ENTITY_DECL.name,
        UpdateEngineError::FILESYSTEM_VERIFIER_ERROR.name,
        UpdateEngineError::USER_CANCELED.name,
        UpdateEngineError::NON_CRITICAL_UPDATE_IN_OOBE.name,
        UpdateEngineError::OMAHA_UPDATE_IGNORED_OVER_CELLULAR.name,
        UpdateEngineError::PAYLOAD_TIMESTAMP_ERROR.name,
        UpdateEngineError::UPDATED_BUT_NOT_ACTIVE.name,
        UpdateEngineError::NO_UPDATE.name,
        UpdateEngineError::ROLLBACK_NOT_POSSIBLE.name,
        UpdateEngineError::FIRST_ACTIVE_OMAHA_PING_SENT_PERSISTENCE_ERROR.name,
        UpdateEngineError::VERITY_CALCULATION_ERROR.name,
        UpdateEngineError::INTERNAL_LIB_CURL_ERROR.name,
        UpdateEngineError::UNRESOLVED_HOST_ERROR.name,
        UpdateEngineError::UNRESOLVED_HOST_RECOVERED.name,
        UpdateEngineError::NOT_ENOUGH_SPACE.name,
        UpdateEngineError::DEVICE_CORRUPTED.name,
        UpdateEngineError::PACKAGE_EXCLUDED_FROM_UPDATE.name,
        UpdateEngineError::POST_INSTALL_MOUNT_ERROR.name,
        UpdateEngineError::OVERLAYFS_ENABLED_ERROR.name,
        UpdateEngineError::UPDATE_PROCESSING.name,
        UpdateEngineError::UPDATE_ALREADY_INSTALLED,
    )

    /**
     * Completion codes returned by update engine indicating that the update
     * was successfully applied.
     */
    private val SUCCEEDED_COMPLETION_CODES: Set<Int> = hashSetOf(
        SUCCESS,
        UPDATED_BUT_NOT_ACTIVE,
    )

    init {
        assert(STRINGS.size == POST_INSTALL_MOUNT_ERROR + 1)
    }

    fun toString(code: Int): String {
        val text = if (code in STRINGS.indices) {
            STRINGS[code]
        } else {
            "<unknown>"
        }

        return "$code/$text"
    }

    fun isUpdateSucceeded(errorCode: Int) = errorCode in SUCCEEDED_COMPLETION_CODES
}
