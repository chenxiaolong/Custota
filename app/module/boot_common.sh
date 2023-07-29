# Copyright (C) 2023  Andrew Gunnerson
#
# This file is part of Custota, based on BCR code.
#
# Custota is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.
#
# Custota is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Custota.  If not, see <http://www.gnu.org/licenses/>.

# ---

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
