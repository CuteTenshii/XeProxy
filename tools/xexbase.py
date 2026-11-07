#!/usr/bin/env python
"""Print the load address range of one or more Xbox 360 xex files.

A DashLaunch system plugin loads only at the base address built into its xex.
Two plugins whose ranges overlap will not both load, and the one listed later
in launch.ini fails silently - no DllMain, no log, nothing on screen. This
reads the base out of each xex so an overlap can be seen rather than guessed.

    python xexbase.py XeProxy.xex Xbdm.xex XeCord.xex HvP2.xex Proto.xex

Copy your plugins off the console first (FATXplorer, FTP, or a USB stick).
Ranges that overlap are called out at the end.
"""

import struct
import sys

XEX_HEADER_IMAGE_BASE_ADDRESS = 0x00010201
XEX_HEADER_ENTRY_POINT = 0x00010100

MODULE_FLAGS = [
    (0x01, 'TITLE_PROCESS'), (0x02, 'TITLE_IMPORTS'), (0x04, 'DEBUGGER'),
    (0x08, 'DLL'), (0x10, 'MODULE_PATCH'), (0x20, 'PATCH_FULL'),
    (0x40, 'PATCH_DELTA'), (0x80, 'USER_MODE'),
]


def read_xex(path):
    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 24 or data[:4] != b'XEX2':
        raise ValueError('not a XEX2 file')

    flags, pe_offset = struct.unpack('>II', data[4:12])
    security_offset = struct.unpack('>I', data[16:20])[0]
    count = struct.unpack('>I', data[20:24])[0]

    headers = {}
    for i in range(count):
        off = 24 + i * 8
        if off + 8 > len(data):
            break
        key, value = struct.unpack('>II', data[off:off + 8])
        headers[key] = value

    base = headers.get(XEX_HEADER_IMAGE_BASE_ADDRESS, 0)

    # The loaded size comes from the security info block, which is plaintext
    # even when the image itself is compressed:
    #   DWORD header_size; DWORD image_size; ...
    # Reading the wrapped PE's SizeOfImage instead would not work here, since
    # on a compressed xex those bytes are unreadable - and the file size is a
    # bad substitute, being several times smaller than the mapped range.
    size = 0
    exact = False
    if security_offset + 8 <= len(data):
        size = struct.unpack('>I', data[security_offset + 4:security_offset + 8])[0]
        exact = size > 0
    if not exact:
        size = len(data)

    return {
        'flags': flags,
        'base': base,
        'size': size,
        'exact': exact,
        'entry': headers.get(XEX_HEADER_ENTRY_POINT, 0),
    }


def main(argv):
    if not argv:
        print(__doc__)
        return 1

    rows = []
    for path in argv:
        try:
            info = read_xex(path)
        except Exception as exc:
            print('%-28s  ERROR: %s' % (path, exc))
            continue

        names = [n for bit, n in MODULE_FLAGS if info['flags'] & bit]
        end = info['base'] + info['size']
        print('%-28s  0x%08X - 0x%08X  %6.1f KB %s  [%s]'
              % (path.split('\\')[-1].split('/')[-1],
                 info['base'], end, info['size'] / 1024.0,
                 '' if info['exact'] else '(size unknown, using file size)',
                 ' | '.join(names) or '-'))
        if info['base']:
            rows.append((path, info['base'], end))

    print('')
    clashes = 0
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a_path, a_lo, a_hi = rows[i]
            b_path, b_lo, b_hi = rows[j]
            if a_lo < b_hi and b_lo < a_hi:
                print('OVERLAP: %s (0x%08X-0x%08X) and %s (0x%08X-0x%08X)'
                      % (a_path, a_lo, a_hi, b_path, b_lo, b_hi))
                clashes += 1
    if not clashes:
        print('No overlaps among the files given.')
    print('Reminder: DashLaunch launch.xex itself occupies 0x91F00000 upward.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
