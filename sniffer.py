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
import socket
import socketserver
import sys
import threading
import time

from constants import *
from util import *


class _KDPassthroughSniffer:
    def __init__(
        self, name, read_connection, write_connection, logger_semaphore, start_time
    ):
        self.name = name
        self.read_connection = read_connection
        self.write_connection = write_connection

        self._logger_semaphore = logger_semaphore
        self._packet_log = []

        self.start_time = start_time

    @property
    def elapsed_time_ms(self):
        return int((time.perf_counter() - self.start_time) * 1000)

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

    def _log(self, message, *args):
        """Buffers log messages until a packet is fully processed so the messages can be sent to the logger thread."""
        self._packet_log.append(message % args)

    def _flush_log(self):
        with self._logger_semaphore:
            for line in self._packet_log:
                print(line)
            print("")

        self._packet_log = []

    def _read_until_packet_leader(self):
        buf = self._read_and_passthrough(4)
        packet_signature = unpack("I", buf)

        discarded_bytes = []
        now = self.elapsed_time_ms

        while packet_signature not in (PACKET_LEADER, CONTROL_PACKET_LEADER):
            discarded_bytes += buf[0]
            buf = buf[1:] + self._read_and_passthrough(1)
            packet_signature = unpack("I", buf)

        if discarded_bytes:
            self._log(
                "[%s] @ %d: Discarded non-KD packet bytes %s",
                self.name,
                now,
                hexformat(discarded_bytes),
            )
            self._flush_log()

        return packet_signature

    def read_packet(self):
        payload = bytearray([])

        packet_signature = self._read_until_packet_leader()

        self._log("[%s] @ %d", self.name, self.elapsed_time_ms)
        self._log(
            "Packet leader: %08x (%s)",
            packet_signature,
            "Packet" if packet_signature == PACKET_LEADER else "ControlPacket",
        )

        buf = self._read_and_passthrough(2)
        packet_type = unpack("H", buf)
        packet_type_name = PACKET_TYPE_TABLE.get(packet_type, "<unknown>")
        self._log("> Packet type: %d (%s)", packet_type, packet_type_name)
        if packet_type_name == "<unknown>":
            self._log("!! Unexpected packet type %04x", packet_type)

        buf = self._read_and_passthrough(2)
        data_size = unpack("H", buf)

        buf = self._read_and_passthrough(4)
        packet_id = unpack("I", buf)

        buf = self._read_and_passthrough(4)
        expected_checksum = unpack("I", buf)

        self._log("> Packet ID: %08x", packet_id)
        self._log("> Data size: %d", data_size)
        self._log("> Checksum: %08x", expected_checksum)

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
            # self._log("Reading trailer...")
            trail = self._read_and_passthrough(1)
            # self._log("Trailer: %x", trail[0])
            if trail[0] != PACKET_TRAILER:
                raise Exception("Invalid packet trailer 0x%x" % trail[0])

        self._log_packet(packet_type, payload)

        self._flush_log()
        return True

    def _log_packet(self, packet_type, payload):
        if packet_type == PACKET_TYPE_KD_STATE_MANIPULATE:
            self._log_state_manipulate(payload)
        elif packet_type == PACKET_TYPE_KD_STATE_CHANGE64:
            self._log_state_change64(payload)
        elif payload:
            self._log("%s", hexformat(payload))

    def _log_state_manipulate(self, payload):
        apiNumber = unpack("I", substr(payload, 0, 4))
        self._log("State Manipulate: %08x", apiNumber)
        self._log(hexformat(substr(payload, 0, 16)))

        if apiNumber == DbgKdWriteBreakPointApi:
            bp = "%08x" % unpack("I", substr(payload, 16, 4))
            handle = unpack("I", substr(payload, 20, 4))
            self._log("Breakpoint %d set at %s", handle, bp)
        elif apiNumber == DbgKdRestoreBreakPointApi:
            handle = unpack("I", substr(payload, 16, 4))
            self._log("Breakpoint %d cleared", handle)
        elif apiNumber == DbgKdGetVersionApi:
            version = substr(payload, 16)
            self._log("VERS: %s", hexformat(version))
        elif apiNumber == DbgKdReadVirtualMemoryApi:
            vmem = substr(payload, 56)
            self._log("VMEM:\n%s", hexasc(vmem))
        elif apiNumber == DbgKdReadPhysicalMemoryApi:
            pmem = substr(payload, 56)
            self._log("PMEM:\n%s", hexasc(pmem))
        elif apiNumber == DbgKdReadControlSpaceApi:
            controlspace = substr(payload, 56)
            self._log("CNTL: %s", hexformat(controlspace))
        else:
            self._log("UNKN: %s", hexasc(payload))

    def _log_state_change64(self, payload):
        newState = unpack("I", substr(payload, 0, 4))
        self._log("State Change: New state: %08x", newState)

        if newState == DbgKdExceptionStateChange:
            # DBGKM_EXCEPTION64
            ex = substr(payload, 32)

            code = unpack("I", substr(ex, 0, 4))
            flags = unpack("I", substr(ex, 4, 4))
            record = unpack("I", substr(ex, 8, 4))
            address = unpack("I", substr(ex, 16, 4))
            parameters = unpack("I", substr(ex, 24, 4))

            if code in STATE_CHANGE_EXCEPTIONS:
                self._log("*** %s ", STATE_CHANGE_EXCEPTIONS[code])
            else:
                self._log("*** Exception %08x ", code)

            self._log("at %08x\n", address)

            self._log("Exception flags = %08x", flags)
            self._log("Exception record = %08x", record)
            self._log("Exception address = %08x", address)
            self._log("Number parameters = %08x", parameters)

            self.running = False

            # my @v = getVersionInfo()
            # version  = v[0]
            # $kernelbase = v[2]
        elif newState == DbgKdLoadSymbolsStateChange:
            # DBGKD_LOAD_SYMBOLS64

            filename = payload[0x3B8:-1]
            filename = filename.decode("utf-8")
            self._log("Load Symbols for '%s'", filename)


class _DebuggerConnection:
    """Handles connection to the debugger VM."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.debugger_socket = socket.socket()
        self.debugger_socket.connect((host, port))
        self._running = True

        self._logger_semaphore = threading.BoundedSemaphore()
        self._debuggee_semaphore = threading.BoundedSemaphore()
        self._debuggee = None

        self.debugger_sniffer = None
        self.start_time = time.perf_counter()

    def register_debuggee(self, handler) -> _KDPassthroughSniffer:
        with self._debuggee_semaphore:
            self._debuggee = handler
            self.debugger_sniffer = _KDPassthroughSniffer(
                "Debugger",
                self.debugger_socket,
                handler.connection,
                self._logger_semaphore,
                self.start_time,
            )

        return _KDPassthroughSniffer(
            "Target",
            handler.connection,
            self.debugger_socket,
            self._logger_semaphore,
            self.start_time,
        )

    def unregister_debuggee(self, _handler):
        with self._debuggee_semaphore:
            self._debuggee = None
            self.debugger_sniffer = None

    def sendall(self, data, flags=0):
        return self.debugger_socket.sendall(data, flags)

    def stop(self):
        with self._debuggee_semaphore:
            self._running = False

    def _debugger_thread_main(self):
        while True:
            with self._debuggee_semaphore:
                if not self._running:
                    break

                sniffer = self.debugger_sniffer

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

    try:
        debugger_thread.start()
        server.serve_forever()
    except KeyboardInterrupt:
        debugger_connection.stop()
        raise


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
