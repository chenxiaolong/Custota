# SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

source "${0%/*}/boot_common.sh" /data/local/tmp/custota.log

# We don't want to give any arbitrary system app permissions to update_engine.
# Thus, we create a new context for custota and only give access to that
# specific type. Magisk currently has no builtin way to modify seapp_contexts,
# so we'll do it manually.

header Creating custota_app domain

"${mod_dir}"/custota-selinux."$(getprop ro.product.cpu.abi)" -ST

header Updating seapp_contexts

seapp_file=/system/etc/selinux/plat_seapp_contexts
seapp_temp_dir=${mod_dir}/seapp_temp
seapp_temp_file=${mod_dir}/seapp_temp/plat_seapp_contexts

mkdir -p "${seapp_temp_dir}"
mount -t tmpfs tmpfs "${seapp_temp_dir}"

# Full path because Magisk runs this script in busybox's standalone ash mode and
# we need Android's toybox version of cp.
/system/bin/cp --preserve=a "${seapp_file}" "${seapp_temp_file}"

cat >> "${seapp_temp_file}" << EOF
user=_app isPrivApp=true name=${app_id} domain=custota_app type=app_data_file levelFrom=all
EOF

mount -o ro,bind "${seapp_temp_file}" "${seapp_file}"

# On some devices, the system time is set too late in the boot process. This,
# for some reason, causes the package manager service to not update the package
# info cache entry despite the mtime of the apk being newer than the mtime of
# the cache entry [1]. This causes the sysconfig file's hidden-api-whitelist
# option to not take effect, among other issues. Work around this by forcibly
# deleting the relevant cache entries on every boot.
#
# [1] https://cs.android.com/android/platform/superproject/+/android-13.0.0_r42:frameworks/base/services/core/java/com/android/server/pm/parsing/PackageCacher.java;l=139

header Clear package manager caches

ls -ldZ "${cli_apk%/*}"
find /data/system/package_cache -name "${app_id}-*" -exec ls -ldZ {} \+

run_cli_apk com.chiller3.custota.standalone.ClearPackageManagerCachesKt

# Bind mount the appropriate CA stores so that update_engine will use the
# regular system CA store.

header Linking CA store

apex_store=/apex/com.android.conscrypt/cacerts
system_store=/system/etc/security/cacerts
google_store=${system_store}_google
standard_store=${system_store}
update_engine_store=${system_store}

if [[ -d "${apex_store}" ]]; then
    standard_store=${apex_store}
fi

if [[ -d "${google_store}" ]]; then
    update_engine_store=${google_store}
fi

echo "Standard trust store: ${standard_store}"
echo "update_engine trust store: ${update_engine_store}"

rm -rf "${mod_dir}"/system/etc/security

if [[ "${standard_store}" != "${update_engine_store}" ]]; then
    mkdir -p "${mod_dir}"/system/etc/security
    # This copies the directory instead of symlinking it because the SELinux
    # policy in newer Android versions no longer allows reading the targets of
    # symlinks labelled with the system_security_cacerts_file type.
    cp -r "${standard_store}" "${mod_dir}${update_engine_store}"

    # Replace the whole directory instead of merging it.
    touch "${mod_dir}${update_engine_store}/.replace"
fi
