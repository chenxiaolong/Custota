#!/usr/bin/env python3

# Copyright (C) 2022-2023  Andrew Gunnerson
#
# This file is part of Custota, based on avbroot code.
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

import argparse
import io
import os
import shutil
import sys
import zipfile


MARKER = b'-----BEGIN CERTIFICATE-----'


def parse_props(raw_prop):
    result = {}

    for line in raw_prop.decode('UTF-8').splitlines():
        k, delim, v = line.partition('=')
        if not delim:
            raise ValueError(f'Malformed line: {repr(line)}')

        result[k.strip()] = v.strip()

    return result


def build_otacerts_zip(certificates):
    stream = io.BytesIO()

    with zipfile.ZipFile(stream, 'w') as z:
        for i, certificate in enumerate(sorted(certificates)):
            # The .x509.pem extension is required
            name = os.path.splitext(os.path.basename(certificate))[0]
            info = zipfile.ZipInfo(f'{i}/{name}.x509.pem')

            with open(certificate, 'rb') as f_in:
                data = f_in.read()

            if MARKER not in data:
                raise ValueError(
                    f'Certificate must be PEM-encoded: {certificate}')

            with z.open(info, 'w') as f_out:
                f_out.write(data)

    return stream.getvalue()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--certificate',
        action='append',
        help='Certificate to add',
    )

    args = parser.parse_args()

    if not args.certificate:
        parser.error('No certificates specified')

    return args


def main():
    args = parse_args()

    with open(os.path.join(sys.path[0], 'module.prop'), 'rb') as f:
        module_prop_raw = f.read()
        module_prop = parse_props(module_prop_raw)

    name = module_prop['id']
    version = module_prop['version'].removeprefix('v')

    module_dir = os.path.join(sys.path[0], '..', 'app', 'module')

    dist_dir = os.path.join(sys.path[0], 'dist')
    os.makedirs(dist_dir, exist_ok=True)

    zip_path = os.path.join(dist_dir, f'{name}-{version}.zip')

    with zipfile.ZipFile(zip_path, 'w') as z:
        file_map = {
            'META-INF/com/google/android/update-binary': {
                'file': os.path.join(module_dir, 'update-binary'),
            },
            'META-INF/com/google/android/updater-script': {
                'file': os.path.join(module_dir, 'updater-script'),
            },
            'module.prop': {
                'data': module_prop_raw,
            },
            'system/etc/security/otacerts.zip': {
                'data': build_otacerts_zip(args.certificate),
            },
        }

        for name, source in sorted(file_map.items()):
            # Build our own ZipInfo to ensure archive is reproducible
            info = zipfile.ZipInfo(name)
            with z.open(info, 'w') as f_out:
                if 'data' in source:
                    f_out.write(source['data'])
                else:
                    with open(source['file'], 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)

    print(zip_path)


if __name__ == '__main__':
    main()
