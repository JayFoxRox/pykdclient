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

import debug_connection
import kd_packet
from constants import *
from util import *


class TeeConnection:
    """Models an interceptor between two connections."""

    def __init__(self, read_connection, write_connection):
        self._read_connection = read_connection
        self._write_connection = write_connection

    def recv(self, max_bytes):
        """Reads up to `max_bytes`, writes them to the write_connection and returns them."""
        buf = self._read_connection.recv(max_bytes)
        if self._write_connection:
            self._write_connection.sendall(buf)
        return buf


class _KDPassthroughSniffer(debug_connection.DebugConnection):
    def __init__(
        self, name, read_connection, write_connection, logger_semaphore, start_time
    ):
        super(_KDPassthroughSniffer, self).__init__(name)

        # Create a tee between the read and write connections, then use it as the
        # read connection for the DebugConnection superclass.
        connection = TeeConnection(read_connection, write_connection)
        self.handle_socket(connection)

        self._logger_semaphore = logger_semaphore
        self._packet_log = []
        self.start_time = start_time

    @property
    def elapsed_time_ms(self):
        return int((time.perf_counter() - self.start_time) * 1000)

    def _log(self, message, *args):
        """Buffers log messages until a packet is fully processed so the messages can be sent to the logger thread."""
        self._packet_log.append(message % args)

    def _flush_log(self):
        with self._logger_semaphore:
            for line in self._packet_log:
                print(line)
            print("")

        self._packet_log = []

    def read_packet(self) -> (kd_packet.KDPacket, bytearray):
        """Reads a single KD packet from the connection and logs it."""
        packet, discarded_bytes = super(_KDPassthroughSniffer, self).read_packet()

        if discarded_bytes:
            self._log(
                "[%s] @ %d: Discarded non-KD packet bytes %s",
                self.endpoint,
                self.elapsed_time_ms,
                hexformat(discarded_bytes),
            )

        self._log_packet(packet)
        self._flush_log()

        return packet, discarded_bytes

    def _log_packet(self, packet: kd_packet.KDPacket) -> None:
        """Logs information about a KDPacket."""

        self._log("[%s] @ %d", self.endpoint, self.elapsed_time_ms)
        self._log("\n".join(packet.basic_log_info))

        packet_type = packet.packet_type
        payload = packet.payload

        if packet_type == PACKET_TYPE_KD_STATE_MANIPULATE:
            self._log_state_manipulate(payload)
        elif packet_type == PACKET_TYPE_KD_STATE_CHANGE64:
            self._log_state_change64(payload)
        elif payload:
            self._log("%s", hexformat(payload))

    def _log_state_manipulate(self, payload):
        apiNumber = unpack_one("I", substr(payload, 0, 4))
        self._log(
            "State Manipulate: %08x (%s)",
            apiNumber,
            STATE_MANIPULATE_TABLE.get(apiNumber, "<unknown>"),
        )

        processor_level = unpack_one("H", substr(payload, 4, 2))
        processor = unpack_one("H", substr(payload, 6, 2))
        return_status = unpack_one("I", substr(payload, 8, 4))

        # self._log(hexformat(substr(payload, 0, 16)))
        self._log(hexformat(payload))

        if apiNumber == DbgKdWriteBreakPointApi:
            bp = "%08x" % unpack_one("I", substr(payload, 16, 4))
            handle = unpack_one("I", substr(payload, 20, 4))
            self._log("Breakpoint %d set at %s", handle, bp)

        elif apiNumber == DbgKdRestoreBreakPointApi:
            handle = unpack_one("I", substr(payload, 16, 4))
            self._log("Breakpoint %d cleared", handle)

        elif apiNumber == DbgKdGetVersionApi:
            self._log_version(payload[16:])

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

    def _log_version(self, payload):
        assert len(payload) == 40
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
        ) = struct.unpack("HHBBHHBBBBHQQQ", payload)
        self._log("Version: %d.%d", major_version, minor_version)
        self._log("Protocol version: %d", protocol_version)
        self._log("KD secondary version: %d", kd_secondary_version)
        self._log("Flags: 0x%04x", flags)
        self._log("Machine type: %d (0x%04x)", machine_type, machine_type)
        self._log("Max packet type: %d", max_packet_type)
        self._log("Max state change: %d", max_state_change)
        self._log("Max manipulate: %d", max_manipulate)
        self._log("Simulation: 0x%02x", simulation)
        self._log("Kernel base: %x", kern_base)
        self._log("PS loaded module list: %x", ps_loaded_module_list)
        self._log("Debugger data list: %x", debugger_data_list)

    def _log_state_change64(self, payload):
        new_state = unpack_one("I", substr(payload, 0, 4))
        self._log(
            "State Change: New state: %08x (%s)",
            new_state,
            STATE_CHANGE_TABLE.get(new_state, "<unknown>"),
        )
        # self._log(hexformat(payload))

        if new_state == DbgKdExceptionStateChange:
            # DBGKM_EXCEPTION64
            ex = substr(payload, 32)

            code = unpack_one("I", substr(ex, 0, 4))
            flags = unpack_one("I", substr(ex, 4, 4))
            record = unpack_one("I", substr(ex, 8, 4))
            address = unpack_one("I", substr(ex, 16, 4))
            parameters = unpack_one("I", substr(ex, 24, 4))

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
        elif new_state == DbgKdLoadSymbolsStateChange:
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
            try:
                sniffer.read_packet()
            except OSError as ex:
                print(f"Failed to read packet: {ex}")
                break


class _DebuggeeHandler(socketserver.StreamRequestHandler):
    """Handles connection to a debuggee VM."""

    def setup(self) -> None:
        super(_DebuggeeHandler, self).setup()
        self.debugger = self.server.debugger
        self.sniffer = self.debugger.register_debuggee(self)

    def finish(self) -> None:
        super(_DebuggeeHandler, self).finish()
        self.debugger.unregister_debuggee(self)

        print(f"Debuggee at {self.client_address[0]} disconnectected\n")

    def handle(self) -> None:
        print(f"Debuggee connected from {self.client_address[0]}\n")

        while True:
            try:
                self.sniffer.read_packet()
            except OSError as ex:
                print(f"Failed to read packet from Debuggee {ex}")
                break
            except ConnectionResetError as ex:
                print(f"Debuggee disconnected: {ex}")
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
        server.shutdown()
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
