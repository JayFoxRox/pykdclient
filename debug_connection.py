"""Abstract connection interface for kernel debugging."""
import os
import pathlib

class DebugConnection:
    """Models a connection to the target device (e.g. FIFO, socket)."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self._connection_write = None
        self._connection_read = None

    def connect(self):
        # FIXME: Add support for TCP sockets too
        # self.client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # self.client.connect(endpoint)

        path = pathlib.Path(self.endpoint)
        if not path.exists():
            def require_fifo_exists(fifo_path):
                path = pathlib.Path(fifo_path)
                if not path.exists():
                    raise Exception(
                        "Qemu requires two pipes with a common base name and '.in' and '.out' suffixes. "
                        "E.g., '/tmp/foo.in' and '/tmp/foo.out'.")

                if not path.is_fifo():
                    raise Exception(f"'{path.name}' is not a fifo.")

            # The naming is from the perspective of qemu, so "in" is written to and "out" is read from.
            write_fifo = f"{self.endpoint}.in"
            read_fifo = f"{self.endpoint}.out"

            require_fifo_exists(write_fifo)
            require_fifo_exists(read_fifo)

            flags = os.O_RDWR
            if os.name == 'nt':
                flags |= os.O_BINARY

            self._connection_write = os.open(write_fifo, flags)
            self._connection_read = os.open(read_fifo, flags)

            return

        if path.is_fifo():
            raise Exception(
                "Qemu requires two pipes with a common base name and '.in' and '.out' suffixes. "
                "E.g., '/tmp/foo.in' and '/tmp/foo.out'.")
        else:
            raise Exception(f"Unsupported connection type {self.endpoint}")

    def disconnect(self):
        pass

    def recv(self, max_bytes):
        """Receives up to `max_bytes` bytes from the connection."""
        return os.read(self._connection_read, max_bytes)

    def send(self, buf):
        return os.write(self._connection_write, buf)

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
            buf = self.recv(wanted - total)

            count = len(buf)
            if count:
                total += count
                outbuf += buf

        return outbuf

    def write(self, buffer):
        """Writes `buffer` to the connection, blocking as necessary."""

        while len(buffer):
            written = self.send(buffer)
            buffer = buffer[written:]
