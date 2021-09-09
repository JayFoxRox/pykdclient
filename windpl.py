#!/usr/bin/env python3
"""Win/xbox KernelDebug client."""

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

# pylint: disable = invalid-name, missing-function-docstring, too-many-instance-attributes, fixme

import argparse
import logging
import os
import pathlib
import sys
import struct
from struct import pack  # pylint: disable = no-name-in-module
import time

from constants import *
from debug_connection import DebugConnection
from util import *
from windpl_extra import logical2physical


class DebugContext:
    """Models a KernelDebug session."""

    def __init__(self) -> None:
        self.start_time = time.perf_counter()
        self.timeout = 10  # max time to wait on packet
        self.running = True

        self.kernelcontext = {}
        self.kernelcontext["peb"] = 0
        self.kernelcontext["pid"] = 0
        self.kernelcontext["eprocess"] = 0
        self.kernelcontext["dtb"] = 0

        self.processcontext = {}
        self.processcontext["peb"] = 0
        self.processcontext["pid"] = 0
        self.processcontext["eprocess"] = 0
        self.processcontext["dtb"] = 0
        self.pcontext = self.kernelcontext
        self.nextpid = 1
        self.breakpoints = {}

        self.curbp = 1
        self.controlspace = 0
        self.controlspacesent = False

        self.client = None

    def connect(self, endpoint):
        # if False:
        #     ds = stat(dev) or die("$!")
        #     if S_ISCHR(ds.mode):
        #         # require Device::SerialPort
        #         # FIXME: serial = tie( *FH, 'Device::SerialPort', "dev" ) or die("Can't tie: $!"
        #         serial.baudrate(115200)
        #         serial.parity("none")
        #         serial.databits(8)
        #         serial.stopbits(1)
        #         serial.handshake("none")
        #         serial.write_settings or die("failed writing settings")
        #         FH.blocking(0)
        #     elif S_ISSOCK(ds.mode):
        #         client = None  # FIXME: IO::Socket::UNIX->new(Type = SOCK_STREAM, Peer = dev) or die("Can't create socket!")
        #     else:
        #         die("dev not a character device or a socket")

        logging.info("Connecting to '%s'", endpoint)

        self.client = DebugConnection(endpoint)
        self.client.connect()

    def run(self):
        logging.info("Waiting for target device...")
        self._sendReset()
        packets = 0
        while True:
            self._handlePacket()
            logging.debug("Processed %d packets\n", packets)
            packets += 1

        # FIXME: windpl_loop.py

    @property
    def elapsed_time(self):
        return time.perf_counter() - self.start_time

    def _handlePacket(self):
        ptype, buf = self._getPacket()

        if ptype == PACKET_TYPE_KD_STATE_MANIPULATE:
            self._handleStateManipulate(buf)
        elif ptype == PACKET_TYPE_KD_DEBUG_IO:
            self._handleDebugIO(buf)
        elif ptype == PACKET_TYPE_KD_STATE_CHANGE64:
            self._handleStateChange(buf)
        elif ptype == PACKET_TYPE_KD_RESET:
            # TODO: check to see if this reset is in response to a reset sent by the debugger script.
            # If not, dump the read buffer and start over.
            pass
        elif ptype == PACKET_TYPE_KD_RESEND:
            logging.warning("!! Ignoring resend request")
        elif len(buf):
            logging.debug("Ignoring packet")

        return ptype, buf

    def _getPacket(self):
        packet_type = None
        payload = bytearray([])
        buf = self.client._read_and_passthrough(4)
        packet_signature = unpack("I", buf)
        if packet_signature in (PACKET_LEADER, CONTROL_PACKET_LEADER):
            logging.debug(
                "[%d] Got packet leader: %08x (%s)",
                int(self.elapsed_time * 1000),
                packet_signature,
                "Packet" if packet_signature == PACKET_LEADER else "ControlPacket",
            )

            buf = self.client._read_and_passthrough(2)
            packet_type = unpack("H", buf)
            packet_type_name = PACKET_TYPE_TABLE.get(packet_type, "<unknown>")
            logging.debug("> Packet type: %d (%s)", packet_type, packet_type_name)
            if packet_type_name == "<unknown>":
                logging.critical("!! Unexpected packet type %04x", packet_type)

            buf = self.client._read_and_passthrough(2)
            data_size = unpack("H", buf)

            buf = self.client._read_and_passthrough(4)
            packet_id = unpack("I", buf)
            self.nextpid = packet_id

            buf = self.client._read_and_passthrough(4)
            expected_checksum = unpack("I", buf)

            logging.debug("> Packet ID: %08x", packet_id)
            logging.debug("> Data size: %d", data_size)
            logging.debug("> Checksum: %08x", expected_checksum)

            if data_size:
                payload = self.client._read_and_passthrough(data_size)

            payload_checksum = generate_checksum(payload)
            if payload_checksum != expected_checksum:
                raise Exception(
                    f"!! Checksum invalid. Expected {expected_checksum} but calculated {payload_checksum}"
                )

            # send ack if it's a non-control packet
            if packet_signature == PACKET_LEADER:
                # packet trailer
                # logging.debug("Reading trailer...")
                trail = self.client._read_and_passthrough(1)
                # logging.debug("Trailer: %x", trail[0])
                if trail[0] == PACKET_TRAILER:
                    # logging.debug("sending Ack")
                    self._sendAck()
                else:
                    raise Exception("Invalid packet trailer 0x%x" % trail[0])
        else:
            logging.warning("Discarding non-KD packet bytes: %08x", packet_signature)
        return packet_type, payload

    def _handleDebugIO(self, buf):  # pylint: disable = no-self-use
        apiNumber = unpack("I", substr(buf, 0, 4))
        if apiNumber == DbgKdPrintStringApi:
            print("DbgPrint: " + substr(buf, 0x10).decode("utf-8"))
        else:
            logging.debug("Ignoring debug IO packet with API number %d", apiNumber)

    def _handleStateChange(self, buf):
        newState = unpack("I", substr(buf, 0, 4))
        logging.debug("State Change: New state: %08x", newState)

        if newState == DbgKdExceptionStateChange:
            # DBGKM_EXCEPTION64
            ex = substr(buf, 32)

            code = unpack("I", substr(ex, 0, 4))
            flags = unpack("I", substr(ex, 4, 4))
            record = unpack("I", substr(ex, 8, 4))
            address = unpack("I", substr(ex, 16, 4))
            parameters = unpack("I", substr(ex, 24, 4))

            if code in STATE_CHANGE_EXCEPTIONS:
                logging.warning("*** %s ", STATE_CHANGE_EXCEPTIONS[code])
            else:
                logging.warning("*** Exception %08x ", code)

            logging.warning("at %08x\n", address)

            logging.warning("Exception flags = %08x", flags)
            logging.warning("Exception record = %08x", record)
            logging.warning("Exception address = %08x", address)
            logging.warning("Number parameters = %08x", parameters)

            self.running = False

            # my @v = getVersionInfo()
            # version  = v[0]
            # $kernelbase = v[2]
        elif newState == DbgKdLoadSymbolsStateChange:
            # DBGKD_LOAD_SYMBOLS64

            filename = buf[0x3B8:-1]
            filename = filename.decode("utf-8")
            logging.debug("Load Symbols for '%s'", filename)

            # nothing to do...

            self._sendDbgKdContinue2()

    def _handleStateManipulate(self, buf):

        apiNumber = unpack("I", substr(buf, 0, 4))
        logging.debug("State Manipulate: %08x", apiNumber)

        if apiNumber == DbgKdWriteBreakPointApi:
            bp = "%08x" % unpack("I", substr(buf, 16, 4))
            handle = unpack("I", substr(buf, 20, 4))
            logging.debug("Breakpoint %d set at %s", handle, bp)
            self.breakpoints[bp] = handle
        elif apiNumber == DbgKdRestoreBreakPointApi:
            handle = unpack("I", substr(buf, 16, 4))
            logging.debug("Breakpoint %d cleared", handle)
        elif apiNumber == DbgKdGetVersionApi:
            version = substr(buf, 16)
            logging.debug("VERS:\n%s", hexformat(version))
        elif apiNumber == DbgKdReadVirtualMemoryApi:
            vmem = substr(buf, 56)
            logging.debug("VMEM:\n%s", hexasc(vmem))
        elif apiNumber == DbgKdReadPhysicalMemoryApi:
            pmem = substr(buf, 56)
            logging.debug("PMEM:\n%s", hexasc(pmem))
        elif apiNumber == DbgKdReadControlSpaceApi:
            controlspace = substr(buf, 56)
            logging.debug("CNTL:\n%s", hexformat(controlspace))
        else:
            logging.debug("UNKN:\n%s", hexasc(buf))

    def _sendAck(self):
        logging.debug("Acking with next PID: %08x", self.nextpid)
        ack_packet = pack(
            "IHHII",
            CONTROL_PACKET_LEADER,
            PACKET_TYPE_KD_ACKNOWLEDGE,
            0,
            self.nextpid,
            0,
        )
        # logging.debug("Ack: %s", hexformat(ack_packet))
        self.client.write(ack_packet)

    def _sendReset(self):
        reset_packet = pack(
            "IHHII", CONTROL_PACKET_LEADER, PACKET_TYPE_KD_RESET, 0, 0x00008080, 0
        )

        logging.debug("Sending reset packet\n\n")
        # print(hexformat(rst)
        self.client.write(reset_packet)

    def _getContext(self):
        context = {}
        self._sendDbgKdGetContext()
        buf = self._waitStateManipulate(DbgKdGetContextApi)

        if len(buf) <= 204:
            return None

        ctx = buf[56:]

        # print("CTXT: ", hexformat($context)
        context["ContextFlags"] = unpack("I", ctx[0:4])
        context["DR0"] = unpack("I", ctx[4:8])
        context["DR1"] = unpack("I", ctx[8 : 8 + 4])
        context["DR2"] = unpack("I", ctx[12 : 12 + 4])
        context["DR3"] = unpack("I", ctx[16 : 16 + 4])
        context["DR6"] = unpack("I", ctx[20 : 20 + 4])
        context["DR7"] = unpack("I", ctx[24 : 24 + 4])
        context["fp.ControlWord"] = unpack("I", ctx[28 : 28 + 4])
        context["fp.StatusWord"] = unpack("I", ctx[32 : 32 + 4])
        context["fp.TagWord"] = unpack("I", ctx[36 : 36 + 4])
        context["fp.ErrorOffset"] = unpack("I", ctx[40 : 40 + 4])
        context["fp.ErrorSelector"] = unpack("I", ctx[44 : 44 + 4])
        context["fp.DataOffset"] = unpack("I", ctx[48 : 48 + 4])
        context["fp.DataSelector"] = unpack("I", ctx[52 : 52 + 4])
        context["fp.RegisterArea"] = ctx[56 : 56 + 80]
        context["fp.Cr0NpxState"] = unpack("I", ctx[136 : 136 + 4])
        context["GS"] = unpack("I", ctx[140 : 140 + 4])
        context["FS"] = unpack("I", ctx[144 : 144 + 4])
        context["ES"] = unpack("I", ctx[148 : 148 + 4])
        context["DS"] = unpack("I", ctx[152 : 152 + 4])
        context["EDI"] = unpack("I", ctx[156 : 156 + 4])
        context["ESI"] = unpack("I", ctx[160 : 160 + 4])
        context["EBX"] = unpack("I", ctx[164 : 164 + 4])
        context["EDX"] = unpack("I", ctx[168 : 168 + 4])
        context["ECX"] = unpack("I", ctx[172 : 172 + 4])
        context["EAX"] = unpack("I", ctx[176 : 176 + 4])
        context["EBP"] = unpack("I", ctx[180 : 180 + 4])
        context["EIP"] = unpack("I", ctx[184:188])
        context["CS"] = unpack("I", ctx[188:192])
        context["Eflags"] = unpack("I", ctx[192:196])
        context["ESP"] = unpack("I", ctx[196:200])
        context["SS"] = unpack("I", ctx[200:204])
        context["leftovers"] = ctx[204:]
        return context

    def _setContext(self, context):
        ctx = pack("I", context["ContextFlags"])
        ctx += pack("I", context["DR0"])
        ctx += pack("I", context["DR1"])
        ctx += pack("I", context["DR2"])
        ctx += pack("I", context["DR3"])
        ctx += pack("I", context["DR6"])
        ctx += pack("I", context["DR7"])
        ctx += pack("I", context["fp.ControlWord"])
        ctx += pack("I", context["fp.StatusWord"])
        ctx += pack("I", context["fp.TagWord"])
        ctx += pack("I", context["fp.ErrorOffset"])
        ctx += pack("I", context["fp.ErrorSelector"])
        ctx += pack("I", context["fp.DataOffset"])
        ctx += pack("I", context["fp.DataSelector"])
        ctx += context["fp.RegisterArea"]
        ctx += pack("I", context["fp.Cr0NpxState"])
        ctx += pack("I", context["GS"])
        ctx += pack("I", context["FS"])
        ctx += pack("I", context["ES"])
        ctx += pack("I", context["DS"])
        ctx += pack("I", context["EDI"])
        ctx += pack("I", context["ESI"])
        ctx += pack("I", context["EBX"])
        ctx += pack("I", context["EDX"])
        ctx += pack("I", context["ECX"])
        ctx += pack("I", context["EAX"])
        ctx += pack("I", context["EBP"])
        ctx += pack("I", context["EIP"])
        ctx += pack("I", context["CS"])
        ctx += pack("I", context["Eflags"])
        ctx += pack("I", context["ESP"])
        ctx += pack("I", context["SS"])
        ctx += context["leftovers"]
        self._sendDbgKdSetContext(ctx)
        self._waitStateManipulate(DbgKdSetContextApi)

    def _getVersionInfo(self):
        logging.info("getVersionInfo")
        # os version, protocol version, kernel base, module list, debugger data
        self._sendDbgKdGetVersion()
        buf = self._waitStateManipulate(DbgKdGetVersionApi)
        if len(buf) > 32:
            v = substr(buf, 16)
            osv = "%d.%d" % (unpack("H", substr(v, 4, 2)), unpack("H", substr(v, 6, 2)))
            pv = unpack("H", substr(v, 8, 2))
            machinetype = unpack("H", substr(v, 12, 2))
            kernbase = unpack("I", substr(v, 16, 4))
            modlist = unpack("I", substr(v, 24, 4))
            ddata = unpack("I", substr(v, 32, 4))
            if pv < 5:
                logging.critical("Debug protocol version %d not supported", pv)
                sys.exit()
            if machinetype and (machinetype != 0x2D):
                logging.critical(
                    "Processor architecture %04x not supported", machinetype
                )
                sys.exit()

            logging.info("Windows version = %s", osv)
            logging.info("Protocol version = %d", pv)
            logging.info("Kernel base = %08x", kernbase)
            logging.info("Module list = %08x", modlist)
            logging.info("Debugger data = %08x", ddata)

            return (osv, pv, kernbase, modlist, ddata)
        return ("0.0", 0, 0, 0, 0)

    def _printVersionData(self):
        v = self._getVersionInfo()
        logging.info("Windows version = %s", v[0])
        logging.info("Protocol version = %d", v[1])
        logging.info("Kernel base = %08x", v[2])
        logging.info("Module list = %08x", v[3])
        logging.info("Debugger data = %08x", v[4])

    # if False:
    #     def getKernelModules():
    #         save = pcontext
    #         pcontext = kernelcontext  # this procedure is kernel context only
    #         modules = []
    #         v = getVersionInfo()
    #         flink = readDword(v[3])
    #         modlist = walkList(flink)
    #         for mod in modlist:
    #
    #             # print("module at %08x\n", $mod
    #             buf = readVirtualMemory(mod, 0x34)
    #             if len(buf) == 0x34:
    #                 base = unpack("I", substr(buf, 0x18, 4))
    #                 if base == 0:
    #                     continue
    #                 entry = unpack("I", substr(buf, 0x1C, 4))
    #                 size = unpack("I", substr(buf, 0x20, 4))
    #                 path = substr(buf, 0x24, 8)
    #                 name = substr(buf, 0x2C, 8)
    #                 modules[base]["name"] = unicodeStructToAscii(name)
    #                 modules[base]["path"] = unicodeStructToAscii(path)
    #                 modules[base]["size"] = size
    #                 modules[base]["entry"] = entry
    #                 pcontext = save
    #         return modules
    #
    #     def unicodeStructToAscii(struct):
    #         if len(struct) != 8:
    #             return
    #         length = unpack("H", substr(struct, 0, 2))
    #         vaddr = unpack("I", substr(struct, 4, 4))
    #         buf = readVirtualMemory(vaddr, length)
    #         if len(buf) == length:
    #             buf = None  # FIXME: =~ s/\x00//g;  # ok not really Unicode to Ascii
    #         return buf

    def _sendManipulateStatePacket(self, d):
        header = pack(
            "IHHII",
            PACKET_LEADER,
            PACKET_TYPE_KD_STATE_MANIPULATE,
            len(d),
            self.nextpid,
            generate_checksum(d),
        )

        logging.debug(
            "< manipulate state:\nHeader:\n%s\nBody:\n%s",
            hexformat(header),
            hexformat(d),
        )
        self.client.write(header)
        self.client.write(d)
        self.client.write(bytes([PACKET_TRAILER]))

    def _sendDbgKdContinue2(self):
        logging.debug("< Sending DbgKdContinueApi2 packet")
        d = bytearray([0] * 56)

        # Manipulate state packet
        d = patch_substr(d, 0, 4, "I", DbgKdContinueApi2)  # API Number
        # d = patch_substr(d, 4, 2, "H", 0x0001)  # Processor level
        # d = patch_substr(d, 6, 2, "H", 0x0001)  # Processor
        d = patch_substr(d, 8, 4, "I", HRESULT_STATUS_SUCCESS)  # Return status

        # Continue2 subpacket
        d = patch_substr(d, 12, 4, "I", HRESULT_STATUS_SUCCESS)  # ContinueStatus
        d = patch_substr(d, 16, 4, "I", 0x00000000)  # TraceFlag
        d = patch_substr(d, 20, 4, "I", 0x00000000)  # DR7
        d = patch_substr(d, 24, 4, "I", 0x00000001)  # CurrentSymbolStart
        d = patch_substr(d, 28, 4, "I", 0x00000001)  # CurrentSymbolEnd

        # substr( $d, 0,  4 ) = pack( "I", $DbgKdContinueApi2 );
        # substr( $d, 8,  4 ) = pack( "I", 0x00010001 );
        # substr( $d, 16, 4 ) = pack( "I", 0x00010001 );
        # substr( $d, 24, 4 ) = pack( "I", 0x400 );        # TraceFlag
        # substr( $d, 28, 4 ) = pack( "I", 0x01 );         # Dr7
        self._sendManipulateStatePacket(d)

    def _sendDbgKdGetVersion(self):

        # print("Sending DbgKdGetVersionApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdGetVersionApi)
        self._sendManipulateStatePacket(d)

    def _sendDbgKdWriteBreakPoint(self, bp):
        bp = hex(bp)

        # print("Sending DbgKdWriteBreakPointApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdWriteBreakPointApi)
        d = patch_substr(d, 16, 4, "I", bp)
        d = patch_substr(d, 20, 4, "I", self.curbp)
        self.curbp += 1
        self._sendManipulateStatePacket(d)

    def _sendDbgKdRestoreBreakPoint(self, bp):
        if bp in self.breakpoints:

            # print("Sending DbgKdRestoreBreakPointApi packet\n"
            d = bytearray([0] * 56)
            d = patch_substr(d, 0, 4, "I", DbgKdRestoreBreakPointApi)
            d = patch_substr(d, 16, 4, "I", self.breakpoints[bp])
            self._sendManipulateStatePacket(d)
            del self.breakpoints[bp]

        else:
            logging.warning("Breakpoint not set at bp")

    def _sendDbgKdReadControlSpace(self):

        # print("Sending DbgKdReadControlSpaceApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", 0x3137)
        d = patch_substr(d, 16, 4, "I", 0x02CC)
        d = patch_substr(d, 24, 4, "I", 84)
        self._sendManipulateStatePacket(d)

    def _sendDbgKdWriteControlSpace(self):

        # print("Sending DbgKdWriteControlSpaceApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", 0x3138)
        d = patch_substr(d, 16, 4, "I", 0x02CC)
        d = patch_substr(d, 24, 4, "I", 84)
        d += self.controlspace
        self._sendManipulateStatePacket(d)
        self.controlspacesent = True

    def _sendDbgKdGetContext(self):

        # print("Sending DbgKdGetContextApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdGetContextApi)
        self._sendManipulateStatePacket(d)

    def _sendDbgKdSetContext(self, ctx):

        # print("Sending DbgKdSetContextApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdSetContextApi)
        d = patch_substr(d, 16, 4, ctx[0:4])
        d += ctx
        self._sendManipulateStatePacket(d)

    def _sendDbgKdReadPhysicalMemory(self, addr, readlen):

        # print("Sending DbgKdReadPhysicalMemoryApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdReadPhysicalMemoryApi)
        d = patch_substr(d, 16, 4, "I", addr)
        d = patch_substr(d, 24, 4, "I", readlen)
        self._sendManipulateStatePacket(d)

    def _sendDbgKdWritePhysicalMemory(self, addr, data):
        writelen = len(data)

        d = pack("III", DbgKdWritePhysicalMemoryApi, addr, writelen)
        d += data
        self._sendManipulateStatePacket(d)

    def _sendDbgKdReadVirtualMemory(self, vaddr, readlen):

        # print("Sending DbgKdReadVirtualMemoryApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdReadVirtualMemoryApi)
        d = patch_substr(d, 16, 4, "I", vaddr)
        d = patch_substr(d, 24, 4, "I", readlen)
        self._sendManipulateStatePacket(d)

    def _sendDbgKdWriteVirtualMemory(self, vaddr, data):
        writelen = len(data)

        # print("Sending DbgKdWriteVirtualMemoryApi packet\n"
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", DbgKdWriteVirtualMemoryApi)
        d = patch_substr(d, 16, 4, "I", vaddr)
        d = patch_substr(d, 24, 4, "I", writelen)
        d += data
        self._sendManipulateStatePacket(d)

    def _readDword(self, addr):

        # print("Reading dword at %08x\n", addr
        buf = self._readVirtualMemory(addr, 4)
        if len(buf) == 4:
            return unpack("I", buf)
        return "failed"

    def _readPhysicalMemory(self, addr, length):
        chunksize = 0x800  # max to request in one packet
        out = bytearray([])
        while length > 0:

            if length < chunksize:
                self._sendDbgKdReadPhysicalMemory(addr, length)
                buf = self._waitStateManipulate(DbgKdReadPhysicalMemoryApi)
                if len(buf) > 56:
                    out += substr(buf, 56)
                    length = 0
            else:
                self._sendDbgKdReadPhysicalMemory(addr, chunksize)
                buf = self._waitStateManipulate(DbgKdReadPhysicalMemoryApi)
                if len(buf) > 56:
                    out += substr(buf, 56)
                    length -= chunksize
                    addr += chunksize
        return out

    def _writePhysicalMemory(self, addr, buf):
        length = len(buf)
        chunksize = 0x800  # max to send in one packet
        offset = 0
        # FIXME: Logic sucks here..
        while length > 0:
            if length < chunksize:
                self._sendDbgKdWritePhysicalMemory(addr, buf)
                self._waitStateManipulate(0x313E)
                length = 0
            else:
                self._sendDbgKdWritePhysicalMemory(addr, substr(buf, offset, chunksize))
                self._waitStateManipulate(0x313E)
                length -= chunksize
                offset += chunksize
                addr += chunksize

    def _writeVirtualMemory(self, addr, buf):
        length = len(buf)
        # FIXME: return unless addr && length
        chunksize = 0x800  # max to send in one packet
        offset = 0
        if self.pcontext["pid"] == 0:
            # FIXME: Logic sucks here..
            while length > 0:
                if length < chunksize:
                    self._sendDbgKdWriteVirtualMemory(addr, buf)
                    self._waitStateManipulate(DbgKdWriteVirtualMemoryApi)
                    length = 0
                else:
                    self._sendDbgKdWriteVirtualMemory(
                        addr, substr(buf, offset, chunksize)
                    )
                    self._waitStateManipulate(DbgKdWriteVirtualMemoryApi)
                    length -= chunksize
                    offset += chunksize
                    addr += chunksize
        else:
            distance_to_page_boundary = 0x1000 - (addr & 0xFFF)
            # FIXME: Logic sucks here..
            if distance_to_page_boundary > length:
                physaddr = logical2physical(addr)
                self._writePhysicalMemory(physaddr, buf)
                return

            physaddr = logical2physical(addr)
            buf = buf[:distance_to_page_boundary]
            self._writePhysicalMemory(physaddr, buf)

            addr += distance_to_page_boundary
            offset += distance_to_page_boundary
            remainder = length - distance_to_page_boundary

            while remainder > 0:
                if remainder < 0x1000:
                    physaddr = logical2physical(addr)
                    self._writePhysicalMemory(physaddr, substr(buf, offset, remainder))
                    remainder = 0
                else:
                    physaddr = logical2physical(addr)
                    self._writePhysicalMemory(physaddr, substr(buf, offset, 0x1000))
                    addr += 0x1000
                    offset += 0x1000
                    remainder -= 0x1000

    # FIXME: Indentation is horrible
    def _readVirtualMemory(self, addr, length):
        # FIXME: return unless addr && length
        chunksize = 0x800  # max to request in one packet
        out = bytearray()
        if self.pcontext["pid"] == 0:
            while length > 0:
                if length < chunksize:
                    self._sendDbgKdReadVirtualMemory(addr, length)
                    buf = self._waitStateManipulate(DbgKdReadVirtualMemoryApi)
                    if len(buf) > 56:
                        out += substr(buf, 56)
                        length = 0
                else:
                    self._sendDbgKdReadVirtualMemory(addr, chunksize)
                    buf = self._waitStateManipulate(DbgKdReadVirtualMemoryApi)
                    if len(buf) > 56:
                        out += substr(buf, 56)
                    length -= chunksize
                    addr += chunksize
            return out

        distance_to_page_boundary = 0x1000 - (addr & 0xFFF)
        if distance_to_page_boundary > length:
            physaddr = logical2physical(addr)
            return self._readPhysicalMemory(physaddr, length)

        physaddr = logical2physical(addr)
        buf = self._readPhysicalMemory(physaddr, distance_to_page_boundary)
        addr += distance_to_page_boundary
        remainder = length - distance_to_page_boundary
        while remainder > 0:
            if remainder < 0x1000:
                physaddr = logical2physical(addr)
                buf += self._readPhysicalMemory(physaddr, remainder)
                remainder = 0
            else:
                physaddr = logical2physical(addr)
                buf += self._readPhysicalMemory(physaddr, 0x1000)
                addr += 0x1000
                remainder -= 0x1000
        return buf

    def _sendDbgKdReboot(self):
        logging.info("Sending DbgKdRebootApi packet")
        d = bytearray([0] * 56)
        d = patch_substr(d, 0, 4, "I", 0x313B)
        self._sendManipulateStatePacket(d)

    def _waitStateManipulate(self, wanted):
        if self.running:
            return None

        logging.debug("Waiting on STATE_MANIPULATE packet")
        # FIXME: Implement a timeout.
        # try:
        while 1:
            ptype, buf = self._handlePacket()
            if ptype == PACKET_TYPE_KD_STATE_MANIPULATE:
                api = unpack("I", substr(buf, 0, 4))
                if api == wanted:
                    break
        # except timeout:
        #     logging.warning("Timeout waiting for %04x packet reply", wanted)
        return buf

    def _getPspCidTable(self):
        pspcidtable = 0
        save = self.pcontext
        self.pcontext = self.kernelcontext  # this procedure is kernel context only
        self._sendDbgKdGetVersion()
        buf = self._waitStateManipulate(DbgKdGetVersionApi)
        pddata = unpack("I", substr(buf, 48, 4))
        if pddata:
            # print("Pointer to debugger data struct is at %08x\n", pddata
            ddata = self._readDword(pddata)
            if ddata != "failed":
                # print("debugger data struct is at %08x\n", ddata
                pspcidtable = self._readDword(ddata + 88)
                if pspcidtable != "failed":
                    # print("PspCidTable is %08x\n", $pspcidtable
                    self.pcontext = save
                    return pspcidtable
        self.pcontext = save
        return 0


def _create_fifos(named_pipe):
    def create(fifo_path):
        path = pathlib.Path(fifo_path)
        if not path.exists():
            logging.debug("Creating fifo at '%s'", fifo_path)
            os.mkfifo(fifo_path, 0o644)
            return

        if not path.is_fifo():
            raise Exception(f"'{path.name}' already exists but is not a fifo.")

    create(f"{named_pipe}.in")
    create(f"{named_pipe}.out")


def main(args):
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    if args.create_fifo:
        _create_fifos(args.named_pipe)

    context = DebugContext()
    context.connect(args.named_pipe)

    context.run()

    return 1


if __name__ == "__main__":

    def _parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "named_pipe",
            help="The path to the named pipe used by xemu",
        )

        parser.add_argument(
            "-c",
            "--create-fifo",
            help="Creates the named pipes if they do not already exist.",
            action="store_true",
        )

        parser.add_argument(
            "-v",
            "--verbose",
            help="Enables verbose logging information",
            action="store_true",
        )

        return parser.parse_args()

    sys.exit(main(_parse_args()))
