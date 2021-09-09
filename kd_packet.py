"""Models a Kernel Debug packet."""

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

import constants
import util


class KDPacket:
    def __init__(
        self, packet_leader, packet_type, packet_id, expected_checksum, payload
    ):
        self.packet_leader = packet_leader
        self.packet_type = packet_type
        self.packet_id = packet_id
        self.expected_checksum = expected_checksum
        self.payload = payload

        self.actual_checksum = util.generate_checksum(payload)

    @property
    def packet_group_name(self) -> str:
        if self.packet_leader == constants.PACKET_LEADER:
            return "Packet"
        return "ControlPacket"

    @property
    def packet_type_name(self) -> str:
        return constants.PACKET_TYPE_TABLE.get(self.packet_type, "<unknown>")

    @property
    def needs_ack(self) -> bool:
        return self.packet_leader == constants.PACKET_LEADER
