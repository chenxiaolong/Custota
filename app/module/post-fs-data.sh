# Copyright (C) 2023  Andrew Gunnerson
#
# This file is part of Custota.
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

# We don't want to give any arbitrary system app permissions to update_engine.
# Thus, we create a new context for custota and only give access to that
# specific type. Magisk currently has no builtin way to modify seapp_contexts,
# so we'll do it manually.
#
# Android's fork of libselinux looks at /dev/selinux/apex_seapp_contexts. It's
# currently not used, but may be used in the future for selinux policy updates
# delivered via an apex image.

source "${0%/*}/boot_common.sh" /data/local/tmp/custota_selinux.log

header Creating custota_app domain

"${mod_dir}"/custota_selinux -ST

header Updating seapp_contexts

cat >> /dev/selinux/apex_seapp_contexts << EOF
user=_app isPrivApp=true name=${app_id} domain=custota_app type=app_data_file levelFrom=all
EOF

restorecon -Rv /dev/selinux
