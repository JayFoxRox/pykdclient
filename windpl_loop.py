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


import re


# s = IO::Select->new()
# $s->add( \*STDIN )
# if (serial):
#  $s->add( \*FH )
# elif (client):
#  $s->add(client)


def match(text, pattern):
    assert pattern[0] == "/"
    assert pattern[-1] == "/"
    return re.search(pattern[1:-1], text)


#
# sendReset()
#
# while (ready = $s->can_read ):
#   for fh (@ready):
#   if ( $fh == \*STDIN ):
#     line = <$fh>
#     if (match(line, '/break/'):
#     print("Sending break...\n"
#     writeDev("b")
#     if ( $running == 1 ):
#       print("Kernel is busy (send break command)\n"
#     elif (match(line, '/processcontext ([0-9A-Fa-f]+)/'):
#     pid = hex($1)
#     if ( pid == 0 ):
#       pcontext = kernelcontext
#       print("Process context is kernel\n"
#     else:
#       eproc = getEprocess(pid)
#       dtb   = readDword( $eproc + 0x18 )
#       peb   = readDword( $eproc + 0x1b0 )
#
#     if ($peb):
#       processcontext['eprocess'] = $eproc
#       processcontext['dtb']    = dtb
#       processcontext['peb']    = $peb
#       processcontext['pid']    = pid
#       pcontext     = \%processcontext
#       print("Implicit process is now %x\n", pid
#       else:
#       print("Invalid PID (PEB not found in eprocess)\n"
#
#     elif (match(line, '/getprocaddress (\S+) (\S+)/'):
#     dll  = $1
#     export = $2
#     addr   = getProcAddress( dll, export )
#     if (addr):
#       print("%s!%s:%08x\n", dll, export, addr
#       else:
#       print("%s!%s not found\n", dll, export
#     elif (match(line, '/listexports ([0-9A-Fa-f]+)/'):
#     listExports( hex($1) )
#     elif (match(line, '/^logical2physical ([0-9A-Fa-f]+)/'):
#     print("%08x -> %08x\n", hex($1), logical2physical( hex($1) )
#     elif (match(line, '/^parsepe ([0-9A-Fa-f]+)/'):
#     my %PE     = parsePE( hex($1) )
#     compiled = localtime( $PE{"TimeDateStamp"] )
#     print("Compiled on $compiled\n"
#     elif (match(line, '/^writevirtualmemory ([0-9A-Fa-f]+) [0-9A-Fa-f][0-9A-Fa-f]/'):
#     chomp($line)
#     my ( $c, addr, @bytes ) = split( /\s+/, $line )
#     sendDbgKdWriteVirtualMemory( hex(addr), join( "", map { chr(hex) } @bytes ) )
#     elif (match(line, '/^(?:messagebox|mb)\s+(.*)\|(.*)/'):
#     title   = $1
#     message = $2
#     injectSUSShellcode( $title, $message )
#     insertApc()
#     elif (match(line, '/^processlist|^listprocess/'):
#     print("Walking process list...\n"
#     my %procs = getProcessList()
#     for ( reverse sort keys %procs ):
#       c = localtime( $procs{$_}{'created'] )
#       print("%04x %s\n", $procs{$_}{'pid'], $procs{$_}{'name']
#       printf
#     "Eprocess: %08x  DTB: %08x  PEB: %08x  Created: %s\n", $_,
#     $procs{$_}{'dtb'], $procs{$_}{'peb'], $c
#       print("Threads: "
#       print(join( " ",
#     map { sprint("%08x", $_ } @{ $procs{$_}{'threads'] } )
#       print("\n\n"
#     elif (match(line, '/^module|^listmodules/'):
#     my %modules
#     if ( pcontext['pid'] == 0 ):
#       %modules = getKernelModules()
#     else:
#       %modules = getUserModules()
#     for ( sort keys %modules ):
#       print("%s\tPath:%s\n", modules[$_}{'name'], modules[$_}{'path']
#       print("base:%08x  " . "size:%08x entry:%08x\n\n", $_, modules[$_}{'size'], modules[$_}{'entry']
#     elif (match(line, '/^findprocessbyname (\S+)/'):
#       name  = $1
#       procs = getProcessList()
#       for proc in procs:
#         c = localtime(proc['created'] )
#         n = proc['name']
#         if ( name.lower() == n.lower() ):
#           #FIXME: !!!
#           #print("%04x %s\n", $procs{$_}{'pid'],
#           #  $procs{$_}{'name']
#           #printf
#           #  "Eprocess: %08x  DTB: %08x  PEB: %08x  Created: %s\n",
#           #  $_, $procs{$_}{'dtb'], $procs{$_}{'peb'], $c
#           #print("Threads: "
#           #print(join( " ",
#           #map { sprint("%08x", $_       @{ $procs{$_}{'threads'] } )
#           #print("\n")
#           break
#     elif (match(line, '/^eprocess ([0-9A-Fa-f]+)/'):
#     ep = getEprocess( hex($1) )
#     sendDbgKdReadVirtualMemory( $ep, 648 )
#     buf = waitStateManipulate(DbgKdReadVirtualMemoryApi)
#     if ( len(buf) > 56 ):
#       eproc = substr( buf, 56 )
#       if ( len($eproc) > 0x20c ):
#     name
#     if ( version > 5 ):
#     $name = substr( $eproc, 0x174, 16 )
#       else:
#     $name = substr( $eproc, 0x1fc, 16 )
#       $name =~ s/\x00//g
#     print("Process name is $name\n"
#     next = unpack( "I", substr( $eproc, 0xa0, 4 ) )
#
#     elif (match(line, '/^bp ([0-9A-Fa-f]+)/'):
#     sendDbgKdWriteBreakPoint($1)
#     elif (match(line, '/^bc ([0-9A-Fa-f]+)/'):
#     sendDbgKdRestoreBreakPoint($1)
#     elif (match(line, '/^bl/'):
#     print("Breakpoints:\n", join( "\n", sort keys %breakpoints ), "\n"
#     elif (match(line, '/^continue/'):
#     sendDbgKdContinue2()
#     $running = 1
#     elif (match(line, '/^getpspcidtable/'):
#     getPspCidTable()
#     elif (match(line, '/^(autocontinue|g)$/'):
#
#     # get/set context to update EIP before continuing
#     my %context = getContext()
#     context['EIP']++
#     setContext(%context)
#     sendDbgKdContinue2()
#     $running = 1
#     elif (match(line, '/^version/'):
#     printVersionData()
#     elif (match(line, '/^readcontrolspace/'):
#     sendDbgKdReadControlSpace()
#     elif (match(line, '/^writecontrolspace/'):
#     if ($controlspace):
#       sendDbgKdWriteControlSpace()
#     else:
#       print("Haven't gotten control space yet!\n"
#     elif (match(line, '/^r (.*)=(.*)/'):
#       reg   = $1
#       val   = $2
#       my %context = getContext()
#       if ( len(reg) < 4 ):
#         reg = uc(reg)
#         if ( exists context[reg} ):
#           if ( reg == "fp.RegisterArea" ):
#             print("Not supported yet.\n"
#           elif ( reg == "leftovers" ):
#             print("Not supported.\n"
#           else:
#             context[reg} = hex(val)
#             setContext(%context)
#             %context = getContext()
#             print("New value of %s is %08x\n", reg, context[reg}
#         else:
#           print("Register reg unknown\n"
#     elif (match(line, '/^r (.*)/'):
#       reg   = $1
#       my %context = getContext()
#       if ( len(reg) < 4 ):
#         reg = uc(reg)
#         if ( exists context[reg} ):
#           if ( reg == "fp.RegisterArea" ):
#             print("%s = \n%s\n", reg, hexprint(reg)
#           else:
#             print("%s = %08x\n", reg, context[reg]
#         else:
#           print("Register reg unknown\n"
#     elif (match(line, '/^r$|^getcontext/'):
#       my %context = getContext()
#       for ( sort keys %context ):
#         if (   ( $_ != "fp.RegisterArea" ) && ( $_ != "leftovers" ) ):
#       print("%s=%08x\n", $_, context[$_}
#     elif (match(line, '/^dw ([0-9A-Fa-f]+)/'):
#       print("%08x: %08x\n", hex($1), readDword( hex($1) )
#     elif (match(line, '/^(?:readvirtualmem|d) ([0-9A-Fa-f]+)/'):
#       vaddr = $1
#       readlen
#       if (match(line, '/(?:readvirtualmem|d) ([0-9A-Fa-f]+) ([0-9A-Fa-f]+)/'):
#           readlen = hex($2)
#           readlen ||= 4
#         buf = readVirtualMemory( hex(vaddr), readlen )
#         print(hexasc(buf)
#     elif (match(line, '/^(?:readphysicalmem|dp) ([0-9A-Fa-f]+)/'):
#       addr = $1
#       readlen
#     if (match(line, '/(?:readphysicalmem|dp) ([0-9A-Fa-f]+) ([0-9A-Fa-f]+)/'):
#       readlen = hex($2)
#       readlen ||= 4
#       sendDbgKdReadPhysicalMemory( hex(addr), readlen )
#     elif (match(line, '/^reboot/'):
#       sendDbgKdReboot()
#     elif (match(line, '/^quit|^exit/'):
#       sys.exit()
#     elif (match(line, '/^reset/'):
#       sendReset()
#     elif ( $fh == \*FH || $fh == client ):
#       handlePacket(0)
#       print("\n\n"
