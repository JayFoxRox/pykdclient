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

import struct

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

    @property
    def basic_log_info(self) -> [str]:
        return [
            "Got packet leader: %08x (%s)"
            % (self.packet_leader, self.packet_group_name),
            "  Type: %d (%s)" % (self.packet_type, self.packet_type_name),
            "  ID: %08x" % self.packet_id,
            "  Data size: %d" % len(self.payload),
            "  Checksum: %08x" % self.expected_checksum,
        ]

    def get_detailed_log(self) -> [str]:
        """Returns detailed logging information about this packet."""
        ret = self.basic_log_info

        if self.packet_type == constants.PACKET_TYPE_KD_STATE_MANIPULATE:
            ret.append("")
            ret.extend(self._log_state_manipulate())
        elif self.packet_type == constants.PACKET_TYPE_KD_STATE_CHANGE64:
            ret.append("")
            ret.extend(self._log_state_change64())
        elif self.payload:
            ret.append("\nPayload:\n%s" % util.hexformat(self.payload))

        return ret

    def _log_state_manipulate(self) -> []:
        apiNumber, processor_level, processor, return_status = struct.unpack(
            "IHHI", self.payload[:12]
        )

        ret = [
            "State Manipulate: %08x (%s)"
            % (apiNumber, constants.STATE_MANIPULATE_TABLE.get(apiNumber, "<unknown>")),
            "Processor level: %04x" % processor_level,
            "Processor: %04x" % processor,
            "Return status: %08x" % return_status,
        ]

        # self._log(hexformat(substr(payload, 0, 16)))

        if apiNumber == constants.DbgKdWriteBreakPointApi:
            bp, handle = struct.unpack("II", self.payload[16:24])
            ret.append("Breakpoint %d set at 0x%08x" % (handle, bp))

        elif apiNumber == constants.DbgKdRestoreBreakPointApi:
            handle = struct.unpack("I", self.payload[16:20])[0]
            ret.append("Breakpoint %d (0x%08x) cleared" % (handle, handle))

        elif apiNumber == constants.DbgKdGetVersionApi:
            ret.extend(self._log_version(self.payload[16:]))

        elif apiNumber == constants.DbgKdReadVirtualMemoryApi:
            vmem = self.payload[56:]
            ret.append("VMEM:\n%s" % util.hexasc(vmem))

        elif apiNumber == constants.DbgKdReadPhysicalMemoryApi:
            pmem = self.payload[56:]
            ret.append("PMEM:\n%s" % util.hexasc(pmem))

        elif apiNumber == constants.DbgKdReadControlSpaceApi:
            controlspace = self.payload[56:]
            ret.append("CNTL: %s" % util.hexformat(controlspace))

        else:
            ret.append("UNKN: %s" % util.hexasc(self.payload))

        ret.extend(["\nRaw payload:\n", util.hexformat(self.payload)])
        return ret

    def _log_version(self, version_payload) -> [str]:
        assert len(version_payload) == 40
        (
            major_version,
            minor_version,
            protocol_version,
            kd_secondary_version,
            flags,
            machine_type,
            max_packet_type,
            max_state_change,
            max_manipulate,
            simulation,
            _unused,
            kern_base,
            ps_loaded_module_list,
            debugger_data_list,
        ) = struct.unpack("HHBBHHBBBBHQQQ", version_payload)

        return [
            "Version: %d.%d" % (major_version, minor_version),
            "Protocol version: %d" % protocol_version,
            "KD secondary version: %d" % kd_secondary_version,
            "Flags: 0x%04x" % flags,
            "Machine type: %d (0x%04x)" % (machine_type, machine_type),
            "Max packet type: %d" % max_packet_type,
            "Max state change: %d" % max_state_change,
            "Max manipulate: %d" % max_manipulate,
            "Simulation: 0x%02x" % simulation,
            "Kernel base: %x" % kern_base,
            "PS loaded module list: %x" % ps_loaded_module_list,
            "Debugger data list: %x" % debugger_data_list,
        ]

    def _log_state_change64(self) -> [str]:
        (
            new_state,
            processor_level,
            processor,
            num_processors,
            thread,
            program_counter,
        ) = struct.unpack("IHHIQQ", self.payload[:32])

        ret = [
            "State change: %08x (%s)"
            % (new_state, constants.STATE_CHANGE_TABLE.get(new_state, "<unknown>")),
            "Processor level: %04x" % processor_level,
            "Processor: %04x" % processor,
            "Num processors: %d" % num_processors,
            "Thread: %16x" % thread,
            "Program counter: %16x" % program_counter,
        ]

        # self._log(hexformat(payload))

        if new_state == constants.DbgKdExceptionStateChange:
            # DBGKM_EXCEPTION64
            ex = self.payload[34:]

            code, flags, record, address, parameters = struct.unpack(
                "IIQQI", self.payload[:28]
            )

            if code in constants.STATE_CHANGE_EXCEPTIONS:
                ret.append("*** %s " % constants.STATE_CHANGE_EXCEPTIONS[code])
            else:
                ret.append("*** Exception %08x " % code)

            ret.extend(
                [
                    "at %08x\n" % address,
                    "Exception flags = %08x" % flags,
                    "Exception record = %08x" % record,
                    "Exception address = %08x" % address,
                    "Number parameters = %08x" % parameters,
                ]
            )

        elif new_state == constants.DbgKdLoadSymbolsStateChange:
            ret.extend(self._log_load_symbols_state_change(self.payload[32:]))

        return ret

    def _log_load_symbols_state_change(self, data):
        ret = []

        pathname_length, dll_base, process_id, checksum, image_size, unload = struct.unpack(
            "IQQIII", data[:36]
        )
        ret.extend([
            "Path name length: %d" % pathname_length,
            "DLL Base addr: %016x" % dll_base,
            "Process ID: %016x" % process_id,
            "Checksum: %d (%08x)" % (checksum, checksum),
            "Image size: %d" % image_size,
            "Unload?: %d" % unload
        ])

        filename = self.payload[0x3B8:-1]  # Ignore the null terminator
        filename = filename.decode("utf-8")
        ret.append("Load Symbols for '%s'" % filename)
        ret.append("Remaining payload:\n%s" % util.hexformat(data[32:]))

        ret.append("\n\nRaw payload:\n")
        ret.append(util.hexformat(self.payload))

        return ret
