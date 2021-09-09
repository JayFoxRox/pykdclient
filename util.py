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
    if length is None:
        return buf[start:]
    return buf[start : start + length]


def patch_substr(buf, start, length, fmt, data=None):
    if data is None:
        return buf[0:start] + fmt + buf[start + length :]

    return buf[0:start] + struct.pack(fmt, data) + buf[start + length :]


def unpack(fmt, data):
    return struct.unpack(fmt, data)[0]  # pylint: disable = no-member


def hexformat(buf):
    length = len(buf)
    if length == 0:
        return None

    b = "0000  "
    c = 0
    for x in buf:
        c += 1
        b += "%02x " % x
        if (c % 16) == 0 and c < length:
            b += "\n%04x " % c

    if b[-1] != "\n":
        b += "\n"

    return b


def hexasc(buf):
    length = len(buf)
    if length == 0:
        return None

    count = 0
    ascii_string = ""
    out = "0000  "
    for x in buf:
        c = ord(x)
        out += "%02x " % c
        if 0x1F < c < 0x7F:
            ascii_string += x
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
    v = 0
    for b in buf:
        v += b
    return v
