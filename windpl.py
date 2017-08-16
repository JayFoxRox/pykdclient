#!/usr/bin/env python3
# win/xbox KD client
#
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

#use IO::Select
#use IO::Socket
#use File::stat
#use Fcntl ':mode'
#use strict

import socket
import sys
import struct

dev = sys.argv[1]
timeout = 10  # max time to wait on packet
running = 1

kernelcontext = {}
kernelcontext['peb']    = 0
kernelcontext['pid']    = 0
kernelcontext['eprocess'] = 0
kernelcontext['dtb']    = 0

processcontext = {}
processcontext['peb']    = 0
processcontext['pid']    = 0
processcontext['eprocess'] = 0
processcontext['dtb']    = 0

pcontext     = kernelcontext

#version
#kernelbase

nextpid = 1

breakpoints = {}

curbp = 1
controlspace = 0
controlspacesent = False

#isserial
#serial
#client

if False:
  ds = stat(dev) or die("$!")
  if (S_ISCHR(ds.mode)):
    #require Device::SerialPort
    #FIXME: serial = tie( *FH, 'Device::SerialPort', "dev" ) or die("Can't tie: $!"
    serial.baudrate(115200)
    serial.parity("none")
    serial.databits(8)
    serial.stopbits(1)
    serial.handshake("none")
    serial.write_settings or die("failed writing settings")
    FH.blocking(0)
  elif (S_ISSOCK(ds.mode)):
    client = None #FIXME: IO::Socket::UNIX->new(Type = SOCK_STREAM, Peer = dev) or die("Can't create socket!")
  else:
    die("dev not a character device or a socket")

#FIXME: Add support for TCP sockets too
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
print("Connecting to '" + dev + "'")
client.connect(dev)

def substr(buf, start, length = None):
  if length == None:
    return buf[start:]
  return buf[start:start + length]

def patch_substr(buf, start, length, fmt, data = None):
  if data == None:
    data = fmt
    return buf[0:start] + fmt + buf[start+length:]
  else:
    return buf[0:start] + struct.pack(fmt, data) + buf[start+length:]
    
def unpack(fmt, data):
  return struct.unpack(fmt, data)[0]

def pack(fmt, data):
  return struct.pack(fmt, data)

def writeDev(data):
  if False:
    if (serial):
      serial.write(data)
    else:
      client.syswrite(data)
  client.send(data)
  
def readLoop(wanted):
  total  = 0
  outbuf = bytearray([])
  while ( total < wanted ):
    if False:
      if (serial):
        (count, buf ) = serial.read(1)
      else:
        #FH.blocking(1)
        count = client.sysread(buf, 1)
        if (count == 0):
          die("eof")
            # print("readLoop count %x\n", ord(buf)
        #FH.blocking(0)
    buf = client.recv(1)   
    count = len(buf)
    if (count):
      total += count
      outbuf += buf
  return outbuf

def hexformat(buf):
  length = len(buf)
  if length == 0:
    return
  b = "0000  "
  c = 0
  for x in buf:
    c += 1
    b += "%02x " % x
    if ( c % 16 ) == 0:
      if ( c < length ):
        b += "\n%04x " % c
  if substr( b, -1, 1 ) != "\n":
    b += "\n"
  return b

#FIXME: Verify behaviour
def cksum(buf):
  v = 0
  for b in buf:
    v += b
  return v

PACKET_LEADER = 0x30303030
CONTROL_PACKET_LEADER = 0x69696969

PACKET_TYPE_UNUSED  = 0
PACKET_TYPE_KD_STATE_CHANGE32   = 1
PACKET_TYPE_KD_STATE_MANIPULATE = 2
PACKET_TYPE_KD_DEBUG_IO   = 3
PACKET_TYPE_KD_ACKNOWLEDGE    = 4
PACKET_TYPE_KD_RESEND     = 5
PACKET_TYPE_KD_RESET    = 6
PACKET_TYPE_KD_STATE_CHANGE64   = 7
PACKET_TYPE_MAX     = 8

def handlePacket():

  ptype, buf = getPacket()
  
  if (len(buf) == 0):
    return
  
  if (ptype == PACKET_TYPE_KD_STATE_MANIPULATE):
    handleStateManipulate(buf)
  elif (ptype == PACKET_TYPE_KD_DEBUG_IO):
    handleDebugIO(buf)
  elif (ptype == PACKET_TYPE_KD_STATE_CHANGE64):
    handleStateChange(buf)
  
  return (ptype, buf)

def getPacket():
  global nextpid
  ptype = None
  payload = bytearray([])
  buf   = readLoop(4)
  plh = unpack( "I", buf )
  if ((plh == PACKET_LEADER) or (plh == CONTROL_PACKET_LEADER)):
    print("Got packet leader: %08x" % plh)
    
    buf = readLoop(2)
    ptype = unpack( "H", buf )
    print("Packet type: " + str(ptype) + "")
    
    buf = readLoop(2)
    bc = unpack( "H", buf )
    print("Byte count: " + str(bc) + "")
    
    buf = readLoop(4)
    pid = unpack( "I", buf )
    nextpid = pid
    print("Packet ID: %08x" % pid)
    
    buf = readLoop(4)
    ck = unpack( "I", buf )
    print("Checksum: %08x" % ck)

    if bc:
      payload = readLoop(bc)
    
    # send ack if it's a non-control packet
    if ( plh == PACKET_LEADER ):
        # packet trailer
        trail = readLoop(1)
        print(hexformat(trail))
        if ( trail[0] == 0xAA ):
          # print("sending Ack\n";#)
          sendAck()
  return (ptype, payload)

# PACKET_TYPE_KD_DEBUG_IO apis
# DBGKD_DEBUG_IO
DbgKdPrintStringApi = 0x00003230
DbgKdGetStringApi = 0x00003231
def handleDebugIO(buf):

  apiNumber = unpack("I", substr(buf, 0, 4))
  if (apiNumber == DbgKdPrintStringApi):
    print("DBG PRINT STRING: " + substr(buf, 0x10).decode('utf-8'))
  
# PACKET_TYPE_KD_STATE_CHANGE states
# X86_NT5_DBGKD_WAIT_STATE_CHANGE64
DbgKdExceptionStateChange   = 0x00003030
DbgKdLoadSymbolsStateChange = 0x00003031

def handleStateChange(buf):

  newState = unpack("I", substr(buf, 0, 4))
  print("State Change: %08x" % newState)
  
  if (newState == DbgKdExceptionStateChange):
    exceptions[0xc0000005] = "EXCEPTION_ACCESS_VIOLATION",
    exceptions[0xc000008c] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    exceptions[0x80000003] = "EXCEPTION_BREAKPOINT",
    exceptions[0x80000002] = "EXCEPTION_DATATYPE_MISALIGNMENT",
    exceptions[0xc000008d] = "EXCEPTION_FLT_DENORMAL_OPERAND",
    exceptions[0xc000008e] = "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    exceptions[0xc000008f] = "EXCEPTION_FLT_INEXACT_RESULT",
    exceptions[0xc0000030] = "EXCEPTION_FLT_INVALID_OPERATION",
    exceptions[0xc0000091] = "EXCEPTION_FLT_OVERFLOW",
    exceptions[0xc0000032] = "EXCEPTION_FLT_STACK_CHECK",
    exceptions[0xc0000033] = "EXCEPTION_FLT_UNDERFLOW",
    exceptions[0x80000001] = "EXCEPTION_GUARD_PAGE",
    exceptions[0xc000001d] = "EXCEPTION_ILLEGAL_INSTRUCTION",
    exceptions[0xc0000006] = "EXCEPTION_IN_PAGE_ERROR",
    exceptions[0xc0000094] = "EXCEPTION_INT_DIVIDE_BY_ZERO",
    exceptions[0xc0000035] = "EXCEPTION_INT_OVERFLOW",
    exceptions[0xc00000fd] = "EXCEPTION_STACK_OVERFLOW"

    # DBGKM_EXCEPTION64
    ex = substr(buf, 32)

    code = unpack("I", substr(ex,0,4))
    flags = unpack("I", substr(ex,4,4))
    record = unpack("I", substr(ex,8,4))
    address = unpack("I", substr(ex,16,4))
    parameters = unpack("I", substr(ex,24,4))

    if (code in exceptions):
      print("*** %s ", exceptions[code])
    else:
      print("*** Exception %08x " % code)
    print("at %08x\n", address)

    print("Exception flags = %08x" % flags)
    print("Exception record = %08x" % record)
    print("Exception address = %08x" % address)
    print("Number parameters = %08x" % parameters)

    running = 0

    # my @v = getVersionInfo()
    # version  = v[0]
    # $kernelbase = v[2]
  elif (newState == DbgKdLoadSymbolsStateChange):
    #DBGKD_LOAD_SYMBOLS64

    filename = substr(buf, 0x3b8)
    filename = filename.decode('utf-8').strip()
    print("Load Symbols for " + filename + "")

    #nothing to do...

    sendDbgKdContinue2()

  
# PACKET_TYPE_KD_STATE_MANIPULATE api numbers
# DBGKD_MANIPULATE_STATE64
DbgKdReadVirtualMemoryApi     = 0x00003130
DbgKdWriteVirtualMemoryApi    = 0x00003131
DbgKdGetContextApi    = 0x00003132
DbgKdSetContextApi    = 0x00003133
DbgKdWriteBreakPointApi     = 0x00003134
DbgKdRestoreBreakPointApi     = 0x00003135
DbgKdContinueApi      = 0x00003136
DbgKdReadControlSpaceApi    = 0x00003137
DbgKdWriteControlSpaceApi     = 0x00003138
DbgKdReadIoSpaceApi     = 0x00003139
DbgKdWriteIoSpaceApi    = 0x0000313A
DbgKdRebootApi    = 0x0000313B
DbgKdContinueApi2     = 0x0000313C
DbgKdReadPhysicalMemoryApi    = 0x0000313D
DbgKdWritePhysicalMemoryApi   = 0x0000313E
DbgKdSetSpecialCallApi  = 0x00003140
DbgKdClearSpecialCallsApi     = 0x00003141
DbgKdSetInternalBreakPointApi     = 0x00003142
DbgKdGetInternalBreakPointApi     = 0x00003143
DbgKdReadIoSpaceExtendedApi   = 0x00003144
DbgKdWriteIoSpaceExtendedApi  = 0x00003145
DbgKdGetVersionApi    = 0x00003146
DbgKdWriteBreakPointExApi     = 0x00003147
DbgKdRestoreBreakPointExApi   = 0x00003148
DbgKdCauseBugCheckApi   = 0x00003149
DbgKdSwitchProcessor    = 0x00003150
DbgKdPageInApi    = 0x00003151
DbgKdReadMachineSpecificRegister  = 0x00003152
DbgKdWriteMachineSpecificRegister   = 0x00003153
DbgKdSearchMemoryApi    = 0x00003156
DbgKdGetBusDataApi    = 0x00003157
DbgKdSetBusDataApi    = 0x00003158
DbgKdCheckLowMemoryApi  = 0x00003159

def handleStateManipulate(buf):

  apiNumber = unpack("I", substr(buf, 0, 4))
  print("State Manipulate: %08x" % apiNumber)

  if ( apiNumber == DbgKdWriteBreakPointApi ):
    bp = "%08x" % unpack( "I", substr( buf, 16, 4 ) )
    handle = unpack( "I", substr( buf, 20, 4 ) )
    print("Breakpoint " + handle + " set at " + bp + "")
    breakpoints[bp] = handle
  elif ( apiNumber == DbgKdRestoreBreakPointApi ):
    handle = unpack( "I", substr( buf, 16, 4 ) )
    print("Breakpoint " + handle + " cleared")
  elif ( apiNumber == DbgKdGetVersionApi ):
    version = substr( buf, 16 )
    print("VERS: " + hexformat(version))
  elif ( apiNumber == DbgKdReadVirtualMemoryApi ):
    vmem = substr( buf, 56 )
    print("VMEM:\n" + hexasc(vmem))
  elif ( apiNumber == DbgKdReadPhysicalMemoryApi ):
    pmem = substr( buf, 56 )
    print("PMEM:\n" + hexasc(pmem))
  elif ( apiNumber == DbgKdReadControlSpaceApi ):
    controlspace = substr( buf, 56 )
    print("CNTL: " + hexformat(controlspace))
  else:
    print("UNKN: " + hexasc(buf))
  









def packetHeader(d):
  header = "\x30\x30\x30\x30".encode('utf-8')  # packet leader
  header += "\x02\x00".encode('utf-8')  # packet type PACKET_TYPE_KD_STATE_MANIPULATE
  header += pack( "H", len(d) )  # sizeof data
  header += pack( "I", nextpid )    # packet id
  header += pack( "I", cksum(d) )    # checksum of data
  return header

def sendAck():
  ack = "\x69\x69\x69\x69\x04\x00\x00\x00\x00\x00\x80\x80\x00\x00\x00\x00".encode('utf-8')
  print(nextpid)
  ack = patch_substr( ack, 8, 4 , "I", nextpid )

  print(hexformat(ack))
  writeDev(ack)

def sendReset():
  rst = "\x69\x69\x69\x69\x06\x00\x00\x00\x00\x00\x80\x80\x00\x00\x00\x00".encode('utf-8')

  # print("Sending reset packet\n"
  # print(hexformat(rst)
  writeDev(rst)


def getContext():
  context = {}
  sendDbgKdGetContext()
  buf = waitStateManipulate(DbgKdGetContextApi)
  if ( len(buf) > 204 ):
    ctx = substr( buf, 56 )

    #print("CTXT: ", hexformat($context)
    context['ContextFlags']   = unpack( "I", substr( ctx, 0,  4 ) )
    context['DR0']  = unpack( "I", substr( ctx, 4,  4 ) )
    context['DR1']  = unpack( "I", substr( ctx, 8,  4 ) )
    context['DR2']  = unpack( "I", substr( ctx, 12, 4 ) )
    context['DR3']  = unpack( "I", substr( ctx, 16, 4 ) )
    context['DR6']  = unpack( "I", substr( ctx, 20, 4 ) )
    context['DR7']  = unpack( "I", substr( ctx, 24, 4 ) )
    context['fp.ControlWord']   = unpack( "I", substr( ctx, 28, 4 ) )
    context['fp.StatusWord']  = unpack( "I", substr( ctx, 32, 4 ) )
    context['fp.TagWord']     = unpack( "I", substr( ctx, 36, 4 ) )
    context['fp.ErrorOffset']   = unpack( "I", substr( ctx, 40, 4 ) )
    context['fp.ErrorSelector'] = unpack( "I", substr( ctx, 44, 4 ) )
    context['fp.DataOffset']  = unpack( "I", substr( ctx, 48, 4 ) )
    context['fp.DataSelector']  = unpack( "I", substr( ctx, 52, 4 ) )
    context['fp.RegisterArea'] = substr( ctx, 56, 80 )
    context['fp.Cr0NpxState'] = unpack( "I", substr( ctx, 136, 4 ) )
    context['GS']     = unpack( "I", substr( ctx, 140, 4 ) )
    context['FS']     = unpack( "I", substr( ctx, 144, 4 ) )
    context['ES']     = unpack( "I", substr( ctx, 148, 4 ) )
    context['DS']     = unpack( "I", substr( ctx, 152, 4 ) )
    context['EDI']    = unpack( "I", substr( ctx, 156, 4 ) )
    context['ESI']    = unpack( "I", substr( ctx, 160, 4 ) )
    context['EBX']    = unpack( "I", substr( ctx, 164, 4 ) )
    context['EDX']    = unpack( "I", substr( ctx, 168, 4 ) )
    context['ECX']    = unpack( "I", substr( ctx, 172, 4 ) )
    context['EAX']    = unpack( "I", substr( ctx, 176, 4 ) )
    context['EBP']    = unpack( "I", substr( ctx, 180, 4 ) )
    context['EIP']    = unpack( "I", substr( ctx, 184, 4 ) )
    context['CS']     = unpack( "I", substr( ctx, 188, 4 ) )
    context['Eflags']   = unpack( "I", substr( ctx, 192, 4 ) )
    context['ESP']    = unpack( "I", substr( ctx, 196, 4 ) )
    context['SS']     = unpack( "I", substr( ctx, 200, 4 ) )
    context['leftovers'] = substr( ctx, 204 )
    return context
  
def setContext(context):
  ctx = pack( "I", context['ContextFlags'] )
  ctx += pack( "I", context['DR0'] )
  ctx += pack( "I", context['DR1'] )
  ctx += pack( "I", context['DR2'] )
  ctx += pack( "I", context['DR3'] )
  ctx += pack( "I", context['DR6'] )
  ctx += pack( "I", context['DR7'] )
  ctx += pack( "I", context['fp.ControlWord'] )
  ctx += pack( "I", context['fp.StatusWord'] )
  ctx += pack( "I", context['fp.TagWord'] )
  ctx += pack( "I", context['fp.ErrorOffset'] )
  ctx += pack( "I", context['fp.ErrorSelector'] )
  ctx += pack( "I", context['fp.DataOffset'] )
  ctx += pack( "I", context['fp.DataSelector'] )
  ctx += context['fp.RegisterArea']
  ctx += pack( "I", context['fp.Cr0NpxState'] )
  ctx += pack( "I", context['GS'] )
  ctx += pack( "I", context['FS'] )
  ctx += pack( "I", context['ES'] )
  ctx += pack( "I", context['DS'] )
  ctx += pack( "I", context['EDI'] )
  ctx += pack( "I", context['ESI'] )
  ctx += pack( "I", context['EBX'] )
  ctx += pack( "I", context['EDX'] )
  ctx += pack( "I", context['ECX'] )
  ctx += pack( "I", context['EAX'] )
  ctx += pack( "I", context['EBP'] )
  ctx += pack( "I", context['EIP'] )
  ctx += pack( "I", context['CS'] )
  ctx += pack( "I", context['Eflags'] )
  ctx += pack( "I", context['ESP'] )
  ctx += pack( "I", context['SS'] )
  ctx += context['leftovers']
  sendDbgKdSetContext(ctx)
  waitStateManipulate(DbgKdSetContextApi)

def getVersionInfo():
  print("getVersionInfo")
  # os version, protocol version, kernel base, module list, debugger data
  sendDbgKdGetVersion()
  buf = waitStateManipulate(DbgKdGetVersionApi)
  if ( len(buf) > 32 ):
    v = substr( buf, 16 )
    osv = "%d.%d" % (unpack( "H", substr( v, 4, 2 ) ), unpack( "H", substr( v, 6, 2 ) ))
    pv    = unpack( "H", substr( v, 8,  2 ) )
    machinetype = unpack( "H", substr( v, 12, 2 ) )
    kernbase  = unpack( "I", substr( v, 16, 4 ) )
    modlist   = unpack( "I", substr( v, 24, 4 ) )
    ddata     = unpack( "I", substr( v, 32, 4 ) )
    if ( pv < 5 ):
      print("Debug protocol version %d not supported" % pv)
      sys.exit()
    if ( machinetype and ( machinetype != 0x2d ) ):
      print("Processor architecture %04x not supported" % machinetype)
      sys.exit()
    
    print("Windows version = %s" %  osv)
    print("Protocol version = %d" % pv)
    print("Kernel base = %08x" %  kernbase)
    print("Module list = %08x" %  modlist)
    print("Debugger data = %08x" %  ddata)

    return ( osv, pv, kernbase, modlist, ddata )
  return ( "0.0", 0, 0, 0, 0 )

def printVersionData():
  v = getVersionInfo()
  print("Windows version = %s" %  v[0])
  print("Protocol version = %d" % v[1])
  print("Kernel base = %08x" %  v[2])
  print("Module list = %08x" %  v[3])
  print("Debugger data = %08x" %  v[4])

if False:
  def getKernelModules():
    save = pcontext
    pcontext = kernelcontext  # this procedure is kernel context only
    modules = []
    v = getVersionInfo()
    flink   = readDword( v[3] )
    modlist = walkList(flink)
    for mod in modlist:

      #print("module at %08x\n", $mod
      buf = readVirtualMemory( mod, 0x34 )
      if ( len(buf) == 0x34 ):
        base = unpack( "I", substr( buf, 0x18, 4 ) )
        if base == 0:
          continue
        entry = unpack( "I", substr( buf, 0x1c, 4 ) )
        size = unpack( "I", substr( buf, 0x20, 4 ) )
        path = substr( buf, 0x24, 8 )
        name = substr( buf, 0x2c, 8 )
        modules[base]['name']  = unicodeStructToAscii(name)
        modules[base]['path']  = unicodeStructToAscii(path)
        modules[base]['size']  = size
        modules[base]['entry'] = entry
        pcontext = save
    return modules

  def unicodeStructToAscii(struct):
    if len(struct) != 8:
      return
    length = unpack( "H", substr( struct, 0, 2 ) )
    vaddr = unpack( "I", substr( struct, 4, 4 ) )
    buf = readVirtualMemory( vaddr, length )
    if ( len(buf) == length ):
      buf = None #FIXME: =~ s/\x00//g;  # ok not really Unicode to Ascii
    return buf
  
def hexasc(buf):
  length = len(buf)
  if length == 0:
    return
  count = 0
  ascii = ""
  out = "0000  "
  for x in buf:
    c = ord(x)
    out += "%02x " % c
    if ( ( c > 0x1f ) and ( c < 0x7f ) ):
      ascii += x
    else:
      ascii += "."
    if ( ++count % 16 ) == 0:
      if ( count < length ):
        out += " " + ascii + "\n%04x  " % count
      else:
        out += " " + ascii + "\n"
        ascii = ""
  if (ascii):
    padding = 48 - ( ( count % 16 ) * 3 )
  out += " " * padding
  out += " " + ascii + "\n"
  return out

def sendManipulateStatePacket(d):
  h = packetHeader(d)

  print("SEND: " + hexformat(h) + hexformat(d))
  writeDev(h)
  writeDev(d)
  writeDev(bytes([0xAA]))

def sendDbgKdContinue2():

  #print("Sending DbgKdContinue2Api packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", DbgKdContinueApi2 )
  d = patch_substr( d, 8,  4 , "I", 0x00010001 )
  d = patch_substr( d, 16, 4 , "I", 0x00010001 )
  d = patch_substr( d, 24, 4 , "I", 0x400 )  # TraceFlag
  d = patch_substr( d, 28, 4 , "I", 0x01 )   # Dr7
  sendManipulateStatePacket(d)

def sendDbgKdGetVersion():

  #print("Sending DbgKdGetVersionApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0, 4 , "I", DbgKdGetVersionApi )
  sendManipulateStatePacket(d)

def sendDbgKdWriteBreakPoint(bp):
  bp = hex(bp)

  #print("Sending DbgKdWriteBreakPointApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", DbgKdWriteBreakPointApi )
  d = patch_substr( d, 16, 4 , "I", bp )
  d = patch_substr( d, 20, 4 , "I", curbp )
  curbp += 1
  sendManipulateStatePacket(d)

def sendDbgKdRestoreBreakPoint(bp):
  if ( defined( breakpoints[bp] ) ):

    #print("Sending DbgKdRestoreBreakPointApi packet\n"
    d = bytearray([0] * 56)
    d = patch_substr( d, 0,  4 , "I", DbgKdRestoreBreakPointApi )
    d = patch_substr( d, 16, 4 , "I", breakpoints[bp] )
    sendManipulateStatePacket(d)
    delete( breakpoints[bp] )
  else:
    print("Breakpoint not set at bp")
  
def sendDbgKdReadControlSpace():

  #print("Sending DbgKdReadControlSpaceApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", 0x3137 )
  d = patch_substr( d, 16, 4 , "I", 0x02cc )
  d = patch_substr( d, 24, 4 , "I", 84 )
  sendManipulateStatePacket(d)

def sendDbgKdWriteControlSpace():

  #print("Sending DbgKdWriteControlSpaceApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", 0x3138 )
  d = patch_substr( d, 16, 4 , "I", 0x02cc )
  d = patch_substr( d, 24, 4 , "I", 84 )
  d += controlspace
  sendManipulateStatePacket(d)
  controlspacesent = 1

def sendDbgKdGetContext():

  #print("Sending DbgKdGetContextApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0, 4 , "I", DbgKdGetContextApi )
  sendManipulateStatePacket(d)

def sendDbgKdSetContext(ctx):

  #print("Sending DbgKdSetContextApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0, 4 , "I", DbgKdSetContextApi )
  d = patch_substr( d, 16, 4, substr( ctx, 0, 4 ))
  d += ctx
  sendManipulateStatePacket(d)

def sendDbgKdReadPhysicalMemory(addr, readlen):

  #print("Sending DbgKdReadPhysicalMemoryApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", DbgKdReadPhysicalMemoryApi )
  d = patch_substr( d, 16, 4 , "I", addr )
  d = patch_substr( d, 24, 4 , "I", readlen )
  sendManipulateStatePacket(d)

def sendDbgKdReadVirtualMemory(vaddr, readlen):

  #print("Sending DbgKdReadVirtualMemoryApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", DbgKdReadVirtualMemoryApi )
  d = patch_substr( d, 16, 4 , "I", vaddr )
  d = patch_substr( d, 24, 4 , "I", readlen )
  sendManipulateStatePacket(d)

def sendDbgKdWriteVirtualMemory(vaddr, data):
  writelen = len(data)

  #print("Sending DbgKdWriteVirtualMemoryApi packet\n"
  d = bytearray([0] * 56)
  d = patch_substr( d, 0,  4 , "I", DbgKdWriteVirtualMemoryApi )
  d = patch_substr( d, 16, 4 , "I", vaddr )
  d = patch_substr( d, 24, 4 , "I", writelen )
  d += data
  sendManipulateStatePacket(d)

def readDword(addr):

  #print("Reading dword at %08x\n", addr
  buf = readVirtualMemory( addr, 4 )
  if ( len(buf) == 4 ):
    return unpack( "I", buf )
  return "failed"

def readPhysicalMemory(addr, length):
  chunksize = 0x800  # max to request in one packet
  out = bytearray([])
  while ( length > 0 ):

    if ( length < chunksize ):
      sendDbgKdReadPhysicalMemory( addr, length )
      buf = waitStateManipulate(DbgKdReadPhysicalMemoryApi)
      if ( len(buf) > 56 ):
        out += substr( buf, 56 )
        length = 0
    else:
      sendDbgKdReadPhysicalMemory( addr, chunksize )
      buf = waitStateManipulate(DbgKdReadPhysicalMemoryApi)
      if ( len(buf) > 56 ):
        out += substr( buf, 56 )
        length -= chunksize
        addr += chunksize
  return out

def writePhysicalMemory(addr, buf):
  length  = len(buf)
  chunksize = 0x800    # max to send in one packet
  offset  = 0
  #FIXME: Logic sucks here..
  while ( length > 0 ):
    if ( length < chunksize ):
      sendDbgKdWritePhysicalMemory( addr, buf )
      waitStateManipulate(0x313e)
      length = 0
    else:
      sendDbgKdWritePhysicalMemory( addr, substr( buf, offset, chunksize ) )
      waitStateManipulate(0x313e)
      length -= chunksize
      offset += chunksize
      addr   += chunksize
  return

def writeVirtualMemory(addr, buf):
  length  = len(buf)
  #FIXME: return unless addr && length
  chunksize = 0x800  # max to send in one packet
  offset  = 0
  if ( pcontext['pid'] == 0 ):
    #FIXME: Logic sucks here..
    while ( length > 0 ):
      if ( length < chunksize ):
        sendDbgKdWriteVirtualMemory( addr, buf )
        waitStateManipulate(DbgKdWriteVirtualMemoryApi)
        length = 0
      else:
        sendDbgKdWriteVirtualMemory( addr, substr( buf, offset, chunksize ) )
        waitStateManipulate(DbgKdWriteVirtualMemoryApi)
        length -= chunksize
        offset += chunksize
        addr   += chunksize
  else:
    distance_to_page_boundary = 0x1000 - ( addr & 0xfff )
    #FIXME: Logic sucks here..
    if ( distance_to_page_boundary > length ):
      physaddr = logical2physical(addr)
      writePhysicalMemory( physaddr, buf )
      return
    else:
      physaddr = logical2physical(addr)
      buf = writePhysicalMemory( physaddr, substr( buf, 0, distance_to_page_boundary ) )
      addr   += distance_to_page_boundary
      offset += distance_to_page_boundary
      remainder = length - distance_to_page_boundary

    while ( remainder > 0 ):
      if ( remainder < 0x1000 ):
        physaddr = logical2physical(addr)
        writePhysicalMemory( physaddr, substr( buf, offset, remainder ) )
        remainder = 0
      else:
        physaddr = logical2physical(addr)
        writePhysicalMemory( physaddr, substr( buf, offset, 0x1000 ) )
        addr   += 0x1000
        offset += 0x1000
        remainder -= 0x1000
    return
  
#FIXME: Indentation is horrible
def readVirtualMemory(addr, length):
  #FIXME: return unless addr && length
  chunksize = 0x800  # max to request in one packet
  out = bytearray()
  buf = bytearray()
  if ( pcontext['pid'] == 0 ):
    while ( length > 0 ):
      if ( length < chunksize ):
        sendDbgKdReadVirtualMemory( addr, length )
        buf = waitStateManipulate(DbgKdReadVirtualMemoryApi)
        if ( len(buf) > 56 ):
          out += substr( buf, 56 )
          length = 0
      else:
        sendDbgKdReadVirtualMemory( addr, chunksize )
        buf = waitStateManipulate(DbgKdReadVirtualMemoryApi)
        if ( len(buf) > 56 ):
          out += substr( buf, 56 )
        length -= chunksize
        addr += chunksize
    return out
  else:
    distance_to_page_boundary = 0x1000 - ( addr & 0xfff )
    if ( distance_to_page_boundary > length ):
      physaddr = logical2physical(addr)
      return readPhysicalMemory( physaddr, length )
    else:
      physaddr = logical2physical(addr)
      buf = readPhysicalMemory( physaddr, distance_to_page_boundary )
      addr += distance_to_page_boundary
      remainder = length - distance_to_page_boundary
      while ( remainder > 0 ):
        if ( remainder < 0x1000 ):
          physaddr = logical2physical(addr)
          buf += readPhysicalMemory( physaddr, remainder )
          remainder = 0
        else:
          physaddr = logical2physical(addr)
          buf += readPhysicalMemory( physaddr, 0x1000 )
          addr += 0x1000
          remainder -= 0x1000
    return buf
  
  
def sendDbgKdReboot():
  print("Sending DbgKdRebootApi packet")
  d = bytearray([0] * 56)
  d = patch_substr( d, 0, 4 , "I", 0x313b )
  sendManipulateStatePacket(d)


def waitStateManipulate(wanted):
  if running:
    return
  
  ptype = bytearray([])
  buf = bytearray([])
  try:
    while (1):
      (ptype, buf) = handlePacket(1)
      if (ptype == PACKET_TYPE_KD_STATE_MANIPULATE):
        api = unpack( "I", substr( buf, 0, 4 ) )
        if (api == wanted):
          break
  except timeout:
    print("Timeout waiting for %04x packet reply" % wanted)
  return buf

def getPspCidTable():
  pspcidtable = 0
  save  = pcontext
  pcontext = kernelcontext  # this procedure is kernel context only
  sendDbgKdGetVersion()
  buf = waitStateManipulate(DbgKdGetVersionApi)
  pddata = unpack( "I", substr( buf, 48, 4 ) )
  if (pddata):
    #print("Pointer to debugger data struct is at %08x\n", pddata
    ddata = readDword(pddata)
    if ( ddata != "failed" ):
      #print("debugger data struct is at %08x\n", ddata
      pspcidtable = readDword( ddata + 88 )
      if ( pspcidtable != "failed" ):
        #print("PspCidTable is %08x\n", $pspcidtable
        pcontext = save
        return pspcidtable
  pcontext = save
  return 0



sendReset()
while(True):
  handlePacket()
  print("")

# FIXME: windpl_loop.py

