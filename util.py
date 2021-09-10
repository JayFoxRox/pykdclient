"""Utility methods"""

# Copyright (C) 2007 SecureWorks, Inc.
# Copyright (C) 2013 espes
# Copyright (C) 2017 Jannik Vogel
#
# This program is free software subject to the terms of the GNU General
# Public License.  You can use, copy, redistribute and/or modify the
# program under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version. You should have received a copy of
# the GNU General Public License along with this program.  If not,
# please see http://www.gnu.org/licenses/ for a copy of the GNU General
# Public License.
#
# The program is subject to a disclaimer of warranty and a limitation of
# liability, as disclosed below.
#
# Disclaimer of Warranty.
#
# THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
# APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
# HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE
# OF THE PROGRAM IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU
# ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, CORRECTION OR
# RECOVERY FROM DATA LOSS OR DATA ERRORS.
#
# Limitation of Liability.
#
# IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
# WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR
# CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
# INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES
# ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT
# NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES
# SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE
# WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

import struct


def substr(buf, start, length=None):
    """Returns a slice of the given buf starting at `start` of length `length`."""
    if length is None:
        return buf[start:]
    return buf[start : start + length]


def patch_substr(buf, start, length, fmt, data=None):
    """Replaces a subslice of the given buffer using struct.pack format specifiers."""
    if data is None:
        return buf[0:start] + fmt + buf[start + length :]

    return buf[0:start] + struct.pack(fmt, data) + buf[start + length :]


def unpack_one(fmt, data):
    """Unpacks a single type from the given data using struct.unpack format specifiers."""
    assert len(fmt) == 1
    return struct.unpack(fmt, data)[0]  # pylint: disable = no-member


def hexformat(buf):
    """Returns a hex dump of the given byte array."""
    length = len(buf)
    if length == 0:
        return None

    ret = "0000  "
    offset = 0
    for value in buf:
        offset += 1
        ret += "%02x " % value
        if (offset % 16) == 0 and offset < length:
            ret += "\n%04x  " % offset

    if ret[-1] != "\n":
        ret += "\n"

    return ret


def hexasc(buf):
    """Returns an ASCII dump of the given byte array."""
    length = len(buf)
    if length == 0:
        return None

    count = 0
    ascii_string = ""
    out = "0000  "
    for value in buf:
        if isinstance(value, str):
            codepoint = ord(value)
        else:
            codepoint = value
        out += "%02x " % codepoint
        if 0x1F < codepoint < 0x7F:
            ascii_string += chr(codepoint)
        else:
            ascii_string += "."
        count += 1
        if (count % 16) == 0:
            if count < length:
                out += " " + ascii_string + "\n%04x  " % count
            else:
                out += " " + ascii_string + "\n"
            ascii_string = ""

    padding = 0
    if ascii_string:
        padding = 48 - ((count % 16) * 3)

    out += " " * padding
    out += " " + ascii_string + "\n"
    return out


def generate_checksum(buf):
    """Generates the KD checksum of the given byte array."""
    checksum = 0
    for value in buf:
        checksum += value
    return checksum
