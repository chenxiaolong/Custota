# Copyright (C) 2023  Andrew Gunnerson
#
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

echo Extracting custota_selinux executable from APK
if ! (unzip "${apk}" -p lib/"${abi}"/libcustota_selinux.so \
    > "${MODPATH}"/custota_selinux \
    && chmod -v +x "${MODPATH}"/custota_selinux); then
    echo "Failed to extract custota_selinux"
    rm -rv "${MODPATH}" 2>&1
    exit 1
fi
