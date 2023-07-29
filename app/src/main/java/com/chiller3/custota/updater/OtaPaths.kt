/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

object OtaPaths {
    /** Path to zip file containing x509 certs for verifying OTA signatures. */
    const val OTACERTS_ZIP = "/system/etc/security/otacerts.zip"

    /** Standard AOSP directory for storing temporary OTA-related files. */
    const val OTA_PACKAGE_DIR = "/data/ota_package"

    /** Name of payload file containing the actual partition images. */
    const val PAYLOAD_NAME = "payload.bin"

    /** Name of [PAYLOAD_NAME]'s header in the property files. */
    const val PAYLOAD_METADATA_NAME = "payload_metadata.bin"

    /** Name of payload properties file containing payload checksums. */
    const val PAYLOAD_PROPERTIES_NAME = "payload_properties.txt"

    /** Name of file listing non-zero byte regions in dm-verity partitions. */
    const val CARE_MAP_NAME = "care_map.pb"

    /** Name of file containing the plain-text representation of the OTA metadata. */
    const val METADATA_NAME = "metadata"
}