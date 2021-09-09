"""Waits for a serial TCP connection from a qemu instance and hands it off to a debugger."""
import socketserver

import debug_connection


class _DebuggeeHandler(socketserver.StreamRequestHandler):
    """Handles connection to a debuggee VM."""

    def setup(self) -> None:
        super().setup()
        self.debugger = self.server.debugger
        client = debug_connection.DebugConnection(self.client_address)
        client.handle_socket(self.connection)

        self.debugger.connection = client

    def finish(self) -> None:
        super().finish()
        print(f"Debuggee at {self.client_address[0]} disconnectected\n")

    def handle(self) -> None:
        print(f"Debuggee connected from {self.client_address[0]}\n")
        self.debugger.run()


def serve(host, port, debugger_connection):
    """Listens for connections at host:port and hands them to the given debugger context."""

    print(f"Waiting for debuggee at {host}:{port}")
    server = socketserver.ThreadingTCPServer((host, port), _DebuggeeHandler)
    server.debugger = debugger_connection

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        server.shutdown()
