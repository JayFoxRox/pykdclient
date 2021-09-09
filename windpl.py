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

import argparse
import logging
import os
import pathlib
import sys

import debug_context
import debug_connection
import server


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

    context = debug_context.DebugContext()
    if args.serve:
        return server.serve(args.host, args.port, context)

    endpoint = None
    if args.named_pipe:
        if args.create_fifo:
            _create_fifos(args.named_pipe)
        endpoint = args.named_pipe
    elif args.port:
        endpoint = (args.host, args.port)
    else:
        raise RuntimeError(f"No supported transport method selected.")

    connection = debug_connection.DebugConnection(endpoint)
    connection.connect()

    context.set_connection(connection)
    context.run()

    return 0


if __name__ == "__main__":

    def _parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-p",
            "--port",
            type=int,
            help="The TCP server port used by qemu.",
        )

        parser.add_argument(
            "--host",
            help="The IP address of the host.",
            default="0.0.0.0",
        )

        parser.add_argument(
            "--serve",
            help="Act as a server (e.g., with qemu `-serial tcp:<host>:<port>`)",
            action="store_true",
        )

        parser.add_argument(
            "-np",
            "--named_pipe",
            help="The path to the named pipe used by qemu.",
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

        args = parser.parse_args()

        if not args.port and not args.named_pipe:
            parser.error("At least one of '--port' or '--named-pipe' must be given.")

        return args

    sys.exit(main(_parse_args()))
