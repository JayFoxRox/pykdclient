"""Abstract connection interface for kernel debugging."""

import logging
import os
import pathlib
import socket


class DebugConnection:
    """Models a connection to the target device (e.g. FIFO, socket)."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self._connection_write = None
        self._connection_read = None

        self._recv = None
        self._send = None

    def connect(self):

        if type(self.endpoint) is tuple:
            self._connect_socket(self.endpoint)
        else:
            self._connect_fifo(self.endpoint)

    def handle_socket(self, connection):
        """Utilizes the given socket as the transport layer."""
        self._connection_read = connection
        self._connection_write = self._connection_read
        self._recv = self._recv_socket
        self._send = self._send_socket

    def _connect_socket(self, host_port):
        logging.info("Connecting to %s:%d", host_port[0], host_port[1])
        self.handle_socket(socket.socket())
        self._connection_read.connect(host_port)

    def _connect_fifo(self, path):
        """Connects via a pair of .in and .out named pipes."""

        logging.info("Connecting to FIFO at '%s'", path)

        def require_fifo_exists(fifo_path):
            path_object = pathlib.Path(fifo_path)
            if not path_object.exists():
                raise Exception(
                    "Qemu requires two pipes with a common base name and '.in' and '.out' suffixes. "
                    "E.g., '/tmp/foo.in' and '/tmp/foo.out'."
                )

            if not path_object.is_fifo():
                raise Exception(f"'{path_object.name}' is not a fifo.")

        # The naming is from the perspective of qemu, so "in" is written to and "out" is read from.
        write_fifo = f"{path}.in"
        read_fifo = f"{path}.out"

        require_fifo_exists(write_fifo)
        require_fifo_exists(read_fifo)

        flags = os.O_RDWR
        if os.name == "nt":
            flags |= os.O_BINARY

        self._connection_write = os.open(write_fifo, flags)
        self._connection_read = os.open(read_fifo, flags)

        self._recv = self._recv_fifo
        self._send = self._send_fifo

    def disconnect(self):
        pass

    def _recv_fifo(self, max_bytes):
        """Receives up to `max_bytes` bytes from the connection."""
        bytes_read = os.read(self._connection_read, max_bytes)
        if len(bytes_read) == 0:
            print("Failed to read from connection")

        return bytes_read

    def _send_fifo(self, buf):
        """Sends some or all of the given buf, returns the number of bytes actually sent."""
        return os.write(self._connection_write, buf)

    def _recv_socket(self, max_bytes):
        """Receives up to `max_bytes` bytes from the connection."""
        bytes_read = self._connection_read.recv(max_bytes)
        if len(bytes_read) == 0:
            print("Failed to read from connection")
        return bytes_read

    def _send_socket(self, buf):
        """Sends some or all of the given buf, returns the number of bytes actually sent."""
        return self._connection_write.send(buf)

    def read(self, wanted):
        """Reads exactly `wanted` bytes from the connection, blocking as necessary."""
        total = 0
        outbuf = bytearray([])
        while total < wanted:
            # if False:
            #     if serial:
            #         (count, buf) = serial.read(1)
            #     else:
            #         # FH.blocking(1)
            #         count = client.sysread(buf, 1)
            #         if count == 0:
            #             die("eof")
            #             # print("client.read count %x\n", ord(buf)
            #         # FH.blocking(0)
            buf = self._recv(wanted - total)

            count = len(buf)
            if count:
                total += count
                outbuf += buf
            else:
                raise ConnectionResetError("Failed to read from connection.")

        return outbuf

    def write(self, buffer):
        """Writes `buffer` to the connection, blocking as necessary."""

        while len(buffer):
            written = self._send(buffer)
            buffer = buffer[written:]
