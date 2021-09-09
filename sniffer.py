#!/usr/bin/env python3
"""Sniffer proxy to process kernel debug traffic."""

# Usage:
# 1. Start the debugger qemu instance with
#    `-serial tcp::<debugger_port>,server,nowait`
# 2. Start this sniffer, passing the <debugger_port> and another arbitrary
#    port (<sniffer_port>)
# 3. Start the debuggee qemu instance with
#    `-serial tcp:<sniffer_ip>:<sniffer_port>`

# pylint: disable = too-many-arguments, too-few-public-methods, too-many-instance-attributes

import argparse
import socket
import socketserver
import sys
import threading
import time

import debug_connection
import kd_packet
from util import *  # pylint: disable = wildcard-import, unused-wildcard-import


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
        super().__init__(name)

        # Create a tee between the read and write connections, then use it as the
        # read connection for the DebugConnection superclass.
        connection = TeeConnection(read_connection, write_connection)
        self.handle_socket(connection)

        self._logger_semaphore = logger_semaphore
        self._packet_log = []
        self.start_time = start_time

    @property
    def elapsed_time_ms(self):
        """Returns the milliseconds elapsed since this sniffer was started."""
        return int((time.perf_counter() - self.start_time) * 1000)

    def _log(self, message, *args):
        """Buffers log messages for later synchronized output."""
        self._packet_log.append(message % args)

    def _flush_log(self):
        with self._logger_semaphore:
            for line in self._packet_log:
                print(line)
            print("")

        self._packet_log = []

    def read_packet(self) -> (kd_packet.KDPacket, bytearray):
        """Reads a single KD packet from the connection and logs it."""
        packet, discarded_bytes = super().read_packet()

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
        self._log("\n".join(packet.get_detailed_log()))


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
        """Registers a StreamRequestHandler modeling the debuggee."""
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
        """Unregisters the previously registered debuggee handler."""
        with self._debuggee_semaphore:
            self._debuggee = None
            self.debugger_sniffer = None

    def sendall(self, data, flags=0):
        """Sends the given data to the debugger."""
        return self.debugger_socket.sendall(data, flags)

    def stop(self):
        """Stops this sniffer."""
        with self._debuggee_semaphore:
            self._running = False

    def debugger_thread_main(self):
        """Thread entrypoint for this debugger instance."""
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
        super().setup()
        self.debugger = self.server.debugger
        self.sniffer = self.debugger.register_debuggee(self)

    def finish(self) -> None:
        super().finish()
        self.debugger.unregister_debuggee(self)

        print(f"Debuggee at {self.client_address[0]} disconnectected\n")

    def handle(self) -> None:
        print(f"Debuggee connected from {self.client_address[0]}\n")

        while True:
            try:
                self.sniffer.read_packet()
            except ConnectionResetError as ex:
                print(f"Debuggee disconnected: {ex}")
                break
            except OSError as ex:
                print(f"Failed to read packet from Debuggee {ex}")
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
        target=_DebuggerConnection.debugger_thread_main, args=(debugger_connection,)
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
