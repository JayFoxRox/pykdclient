#!/usr/bin/env python3
"""Sniffer proxy to process kernel debug traffic."""

# Usage:
# 1. Start the debugger qemu instance with
#    `-serial tcp::<debugger_port>,server,nowait`
# 2. Start this sniffer, passing the <debugger_port> and another arbitrary
#    port (<sniffer_port>)
# 3. Start the debuggee qemu instance with
#    `-serial tcp:<sniffer_ip>:<sniffer_port>`

import argparse
import logging
import socket
import socketserver
import sys
import threading
import time

from constants import *
from util import *


class _KDPassthroughSniffer:
    def __init__(self, name, read_connection, write_connection):
        self.name = name
        self.read_connection = read_connection
        self.write_connection = write_connection

    def _read(self, wanted):
        """Reads exactly `wanted` bytes from the connection, blocking as necessary."""
        total = 0
        ret = bytearray([])
        while total < wanted:
            buf = self.read_connection.recv(wanted - total)
            count = len(buf)
            if count:
                total += count
                ret += buf

        return ret

    def _read_and_passthrough(self, wanted):
        ret = self._read(wanted)
        if self.write_connection:
            # TODO: Handle exception when the target socket is closed.
            self.write_connection.sendall(ret)
        return ret

    def read_packet(self):
        payload = bytearray([])
        buf = self._read_and_passthrough(4)
        packet_signature = unpack("I", buf)

        if packet_signature in (PACKET_LEADER, CONTROL_PACKET_LEADER):
            logging.debug("\n\n[%s]", self.name)
            logging.debug(
                "Packet leader: %08x (%s)",
                packet_signature,
                "Packet" if packet_signature == PACKET_LEADER else "ControlPacket",
            )

            buf = self._read_and_passthrough(2)
            packet_type = unpack("H", buf)
            packet_type_name = PACKET_TYPE_TABLE.get(packet_type, "<unknown>")
            logging.debug("> Packet type: %d (%s)", packet_type, packet_type_name)
            if packet_type_name == "<unknown>":
                logging.critical("!! Unexpected packet type %04x", packet_type)

            buf = self._read_and_passthrough(2)
            data_size = unpack("H", buf)

            buf = self._read_and_passthrough(4)
            packet_id = unpack("I", buf)

            buf = self._read_and_passthrough(4)
            expected_checksum = unpack("I", buf)

            logging.debug("> Packet ID: %08x", packet_id)
            logging.debug("> Data size: %d", data_size)
            logging.debug("> Checksum: %08x", expected_checksum)

            if data_size:
                payload = self._read_and_passthrough(data_size)

            payload_checksum = generate_checksum(payload)
            if payload_checksum != expected_checksum:
                raise Exception(
                    f"!! Checksum invalid. Expected {expected_checksum} but calculated {payload_checksum}"
                )

            # send ack if it's a non-control packet
            if packet_signature == PACKET_LEADER:
                # packet trailer
                # logging.debug("Reading trailer...")
                trail = self._read_and_passthrough(1)
                # logging.debug("Trailer: %x", trail[0])
                if trail[0] != PACKET_TRAILER:
                    raise Exception("Invalid packet trailer 0x%x" % trail[0])

            self._log_packet(packet_type, payload)
        else:
            logging.warning("Discarding non-KD packet bytes: %08x", packet_signature)

        return True

    def _log_packet(self, packet_type, payload):
        if packet_type == PACKET_TYPE_KD_STATE_MANIPULATE:
            self._log_state_manipulate(payload)
        elif packet_type == PACKET_TYPE_KD_STATE_CHANGE64:
            self._log_state_change64(payload)
        elif payload:
            logging.debug("%s", hexformat(payload))

    def _log_state_manipulate(self, payload):
        apiNumber = unpack("I", substr(payload, 0, 4))
        logging.debug("State Manipulate: %08x", apiNumber)

        if apiNumber == DbgKdWriteBreakPointApi:
            bp = "%08x" % unpack("I", substr(payload, 16, 4))
            handle = unpack("I", substr(payload, 20, 4))
            logging.debug("Breakpoint %d set at %s", handle, bp)
        elif apiNumber == DbgKdRestoreBreakPointApi:
            handle = unpack("I", substr(payload, 16, 4))
            logging.debug("Breakpoint %d cleared", handle)
        elif apiNumber == DbgKdGetVersionApi:
            version = substr(payload, 16)
            logging.debug("VERS: %s", hexformat(version))
        elif apiNumber == DbgKdReadVirtualMemoryApi:
            vmem = substr(payload, 56)
            logging.debug("VMEM:\n%s", hexasc(vmem))
        elif apiNumber == DbgKdReadPhysicalMemoryApi:
            pmem = substr(payload, 56)
            logging.debug("PMEM:\n%s", hexasc(pmem))
        elif apiNumber == DbgKdReadControlSpaceApi:
            controlspace = substr(payload, 56)
            logging.debug("CNTL: %s", hexformat(controlspace))
        else:
            logging.debug("UNKN: %s", hexasc(payload))

    def _log_state_change64(self, payload):
        newState = unpack("I", substr(payload, 0, 4))
        logging.debug("State Change: New state: %08x", newState)

        if newState == DbgKdExceptionStateChange:
            # DBGKM_EXCEPTION64
            ex = substr(payload, 32)

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

            filename = payload[0x3B8:-1]
            filename = filename.decode("utf-8")
            logging.debug("Load Symbols for '%s'", filename)


class _DebuggerConnection:
    """Handles connection to the debugger VM."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.debugger_socket = socket.socket()
        self.debugger_socket.connect((host, port))

        self.debuggee_semaphore = threading.BoundedSemaphore()
        self.debuggee = None

        self.sniffer = None

    def register_debuggee(self, handler) -> _KDPassthroughSniffer:
        with self.debuggee_semaphore:
            self.debuggee = handler
            self.sniffer = _KDPassthroughSniffer(
                "Debugger", self.debugger_socket, handler.connection
            )
        return _KDPassthroughSniffer("Target", handler.connection, self.debugger_socket)

    def unregister_debuggee(self, _handler):
        with self.debuggee_semaphore:
            self.debuggee = None

    def sendall(self, data, flags=0):
        return self.debugger_socket.sendall(data, flags)

    def _debugger_thread_main(self):
        while True:
            with self.debuggee_semaphore:
                sniffer = self.sniffer
            if not sniffer:
                time.sleep(0.100)
                continue

            # TODO: Make this handle unregistration gracefully.
            sniffer.read_packet()


class _DebuggeeHandler(socketserver.StreamRequestHandler):
    """Handles connection to a debuggee VM."""

    def setup(self) -> None:
        super(_DebuggeeHandler, self).setup()
        self.debugger = self.server.debugger
        self.sniffer = self.debugger.register_debuggee(self)

    def finish(self) -> None:
        super(_DebuggeeHandler, self).finish()
        self.debugger.unregister_debuggee(self)

    def handle(self) -> None:
        print(f"Debuggee connected from {self.client_address[0]}")

        while True:
            if not self.sniffer.read_packet():
                break


def main(args):
    """Main entrypoint"""
    logging.basicConfig(level=logging.DEBUG)

    print(f"Connecting to debugger at {args.debugger_ip}:{args.debugger_port}")
    debugger_connection = _DebuggerConnection(args.debugger_ip, args.debugger_port)

    print(f"Listening for debuggee at {args.sniffer_ip}:{args.sniffer_port}")
    server = socketserver.ThreadingTCPServer(
        (args.sniffer_ip, args.sniffer_port), _DebuggeeHandler
    )
    server.debugger = debugger_connection

    debugger_thread = threading.Thread(
        target=_DebuggerConnection._debugger_thread_main, args=(debugger_connection,)
    )
    debugger_thread.start()
    server.serve_forever()


if __name__ == "__main__":

    def _parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "debugger_port",
            type=int,
            help="The port used by the VM hosting the debugger.",
        )

        parser.add_argument(
            "sniffer_port",
            type=int,
            help="The port that the debuggee's COM port should connect to instead of the VM port.",
        )

        parser.add_argument(
            "-dip",
            "--debugger_ip",
            help="The IP address on which the debugger VM is listening.",
            default="localhost",
        )

        parser.add_argument(
            "-sip",
            "--sniffer_ip",
            help="The IP address on which the sniffer will listen for the debuggee.",
            default="0.0.0.0",
        )

        return parser.parse_args()

    sys.exit(main(_parse_args()))
