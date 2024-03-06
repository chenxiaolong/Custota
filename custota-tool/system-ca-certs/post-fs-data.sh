exec >/data/local/tmp/system-ca-certs.log 2>&1
set -eux

mod_dir=${0%/*}
apex_dir=/apex/com.android.conscrypt/cacerts
system_dir=/system/etc/security/cacerts
mnt_base=${mod_dir}/mnt
mnt_index=0

rm -rf "${mnt_base}"
mkdir "${mnt_base}"

for cert_dir in "${apex_dir}" "${system_dir}"; do
    if [[ ! -d "${cert_dir}" ]]; then
        continue
    fi

    mnt_dir=${mnt_base}/${mnt_index}
    let mnt_index+=1

    mkdir "${mnt_dir}"
    mount -t tmpfs tmpfs "${mnt_dir}"

    cp -r "${cert_dir}/." "${mnt_dir}"
    cp -r "${mod_dir}/cacerts/." "${mnt_dir}"

    context=$(ls -Zd "${cert_dir}" | awk '{print $1}')
    chcon -R "${context}" "${mnt_dir}"

    nsenter --mount=/proc/1/ns/mnt -- \
        mount -o bind "${mnt_dir}" "${cert_dir}"
done
