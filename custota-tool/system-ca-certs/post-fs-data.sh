exec >/data/local/tmp/system-ca-certs.log 2>&1
set -eux

mod_dir=${0%/*}

module_prop() {
    grep "^${1}=" "${mod_dir}/module.prop" | cut -d= -f2
}

# toybox's `mountpoint` command only works for directories, but bind mounts can
# be files too.
has_mountpoint() {
    local mnt=${1}

    awk -v "mnt=${mnt}" \
        'BEGIN { ret=1 } $5 == mnt { ret=0; exit } END { exit ret }' \
        /proc/self/mountinfo
}

module_id=$(module_prop id)
apex_dir=/apex/com.android.conscrypt/cacerts
system_dir=/system/etc/security/cacerts
mnt_base=${mod_dir}/mnt
mnt_index=0

mkdir -p "${mnt_base}"

for cert_dir in "${apex_dir}" "${system_dir}"; do
    if [[ ! -d "${cert_dir}" ]]; then
        continue
    fi

    mnt_dir=${mnt_base}/${mnt_index}
    let mnt_index+=1

    mkdir -p "${mnt_dir}"
    nsenter --mount=/proc/1/ns/mnt -- \
        mount -t tmpfs "${module_id}" "${mnt_dir}"

    cp -r "${cert_dir}/." "${mnt_dir}"
    cp -r "${mod_dir}/cacerts/." "${mnt_dir}"

    context=$(ls -Zd "${cert_dir}" | awk '{print $1}')
    chcon -R "${context}" "${mnt_dir}"

    while has_mountpoint "${cert_dir}"; do
        umount -l "${cert_dir}"
    done

    nsenter --mount=/proc/1/ns/mnt -- \
        mount -o ro,bind "${mnt_dir}" "${cert_dir}"
done
