#!/usr/bin/env python3

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

import argparse
import dataclasses
import json
import os
import sys
import urllib.parse
import zipfile


@dataclasses.dataclass
class PropertyFile:
    name: str
    offset: int
    size: int


def parse_property_files(value):
    data = {}

    for entry in value.split(','):
        pieces = entry.split(':')
        if len(pieces) != 3:
            raise ValueError(f'Invalid property files entry: {entry}')

        name = pieces[0]
        offset = int(pieces[1])
        size = int(pieces[2])

        if name in data:
            raise ValueError(f'Duplicate property file name: {name}')

        data[name] = (offset, size)

    return data


def parse_ota_metadata(path):
    data = {}

    with zipfile.ZipFile(path, 'r') as z:
        with z.open('META-INF/com/android/metadata', 'r') as f:
            for line in f:
                key, delim, value = line.decode('UTF-8').strip().partition('=')
                if not delim:
                    raise ValueError(f'Invalid line: {line}')

                if key in data:
                    raise ValueError(f'Duplicate key: {key}')

                data[key] = value

    return data


def url_or_relative_path(arg):
    parsed = urllib.parse.urlparse(arg)

    if not parsed.scheme:
        if os.path.isabs(arg):
            raise argparse.ArgumentTypeError(f'Not a relative path: {arg}')
    elif parsed.scheme not in ('http', 'https'):
        raise argparse.ArgumentTypeError(
            f'Only http:// and https:// URLs are supported: {arg}')

    return arg


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-l', '--location',
        type=url_or_relative_path,
        help='Override the OTA location with a URL or relative path',
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to output metadata JSON file '
             '(default: <device codename>.json)',
    )
    parser.add_argument(
        'ota_zip',
        help='Path to OTA file',
    )

    args = parser.parse_args()

    if os.path.isabs(args.ota_zip) and args.location is None:
        parser.error('-l <location> is required when specifying an absolute '
                     f'path: {args.ota_zip}')

    return args


def main():
    args = parse_args()

    ota_metadata = parse_ota_metadata(args.ota_zip)
    device = ota_metadata['pre-device']
    assert os.path.basename(device) == device and device not in ('.', '..')

    expected_name = f'{device}.json'
    if args.output is None:
        output = expected_name
    else:
        output = args.output
        if os.path.basename(output) != expected_name:
            print('Warning: Output filename does not match expected name:',
                  expected_name)

    location = args.location
    if location is None:
        location = os.path.basename(args.ota_zip)

    property_files = parse_property_files(ota_metadata['ota-property-files'])

    update_metadata = {
        'full': {
            'location': location,
            'metadata_offset': property_files['metadata'][0],
            'metadata_size': property_files['metadata'][1],
        },
    }

    with open(output, 'w') as f:
        json.dump(update_metadata, f, indent=4)

    print('Wrote:', output, file=sys.stderr)


if __name__ == '__main__':
    main()
