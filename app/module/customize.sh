# SPDX-FileCopyrightText: 2023 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

# The Android gradle plugin doesn't have a way to build native executables and
# make the outputs available to other tasks. Ideally, the executables would just
# be added to the module zip, but instead, we're forced to rename the files with
# a .so extension and bundle them into the .apk. We'll extract those here.

app_id=$(grep '^id=' "${MODPATH}/module.prop" | cut -d= -f2)
apk=$(find "${MODPATH}"/system/priv-app/"${app_id}" -name '*.apk')
abi=$(getprop ro.product.cpu.abi)

echo "App ID: ${app_id}"
echo "APK: ${apk}"
echo "ABI: ${abi}"

run() {
    echo 'Extracting custota_selinux executable from APK'
    if ! (unzip "${apk}" -p lib/"${abi}"/libcustota_selinux.so \
            > "${MODPATH}"/custota_selinux \
            && chmod -v +x "${MODPATH}"/custota_selinux); then
        echo "Failed to extract custota_selinux"
        return 1
    fi

    echo 'Setting up update_engine CA trust store'
    local ca_dir=${MODPATH}/system/etc/security/cacerts_google
    local apex_ca_dir=/apex/com.android.conscrypt/cacerts
    local system_ca_dir=/system/etc/security/cacerts
    if [[ -d "${apex_ca_dir}" ]]; then
        echo '- Using APEX CA certs as system'
        system_ca_dir=${apex_ca_dir}
    else
        echo '- No APEX CA certs'
    fi
    local user_base_dir=/data/misc/user/0
    local user_ca_added=${user_base_dir}/cacerts-added
    local user_ca_removed=${user_base_dir}/cacerts-removed
    local f

    mkdir -p "${ca_dir}"

    echo '- Copying system CA certs'
    cp -r "${system_ca_dir}"/. "${ca_dir}" || return 1

    if [[ -d "${user_ca_added}" ]]; then
        echo '- Copying user CA certs'
        cp -r "${user_ca_added}"/. "${ca_dir}" || return 1
    else
        echo '- No user CA certs'
    fi

    if [[ -d "${user_ca_removed}" ]]; then
        echo '- Removing disabled CA certs'
        for f in "${user_ca_removed}"/*; do
            rm "${ca_dir}/${f##*/}" || return 1
        done
    fi

    echo '-----------------------------------'
    echo 'NOTE: Custota needs to be reflashed'
    echo 'if CA certificates are changed.'
    echo '-----------------------------------'
}

if ! run 2>&1; then
    rm -rv "${MODPATH}" 2>&1
    exit 1
fi
