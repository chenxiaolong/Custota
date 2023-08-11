# SPDX-FileCopyrightText: 2023 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only
# Based on BCR code.

# source "${0%/*}/boot_common.sh" <log file>

exec >"${1}" 2>&1

mod_dir=${0%/*}

header() {
    echo "----- ${*} -----"
}

module_prop() {
    grep "^${1}=" "${mod_dir}/module.prop" | cut -d= -f2
}

app_id=$(module_prop id)
app_version=$(module_prop version)

header Environment
echo "Timestamp: $(date)"
echo "Script: ${0}"
echo "App ID: ${app_id}"
echo "App version: ${app_version}"
echo "UID/GID/Context: $(id)"
