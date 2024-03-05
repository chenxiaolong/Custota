# SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

# We don't want to give any arbitrary system app permissions to update_engine.
# Thus, we create a new context for custota and only give access to that
# specific type. Magisk currently has no builtin way to modify seapp_contexts,
# so we'll do it manually.

source "${0%/*}/boot_common.sh" /data/local/tmp/custota_selinux.log

header Creating custota_app domain

"${mod_dir}"/custota_selinux -ST

header Updating seapp_contexts

seapp_dir=/system/etc/selinux
seapp_file=${seapp_dir}/plat_seapp_contexts
mod_seapp_dir=${mod_dir}${seapp_dir}
mod_seapp_file=${mod_dir}${seapp_file}

rm -rf "${mod_seapp_dir}"
mkdir -p "${mod_seapp_dir}"

# If, for whatever reason, we couldn't wipe the directory, mount a blank tmpfs
# on top. An outdated file can cause the system to boot loop due to system apps
# running under the wrong SELinux context.
if [[ -e "${mod_seapp_file}" ]]; then
    mount -t tmpfs tmpfs "${mod_seapp_dir}"
fi

# Full path because Magisk runs this script in busybox's standalone ash mode and
# we need Android's toybox version of cp.
/system/bin/cp --preserve=a "${seapp_file}" "${mod_seapp_file}"

cat >> "${mod_seapp_file}" << EOF
user=_app isPrivApp=true name=${app_id} domain=custota_app type=app_data_file levelFrom=all
EOF
