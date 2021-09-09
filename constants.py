"""Constants used by the Kernel Debug protocol."""

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

# Constants are allowed to be camel case to match definitions in ReactOS source.
# pylint: disable = invalid-name

INITIAL_PACKET_ID = 0x80800000
SYNC_PACKET_ID = 0x00000800

PACKET_LEADER = 0x30303030
CONTROL_PACKET_LEADER = 0x69696969
PACKET_TRAILER = 0xAA

PACKET_TYPE_UNUSED = 0
PACKET_TYPE_KD_STATE_CHANGE32 = 1
PACKET_TYPE_KD_STATE_MANIPULATE = 2
PACKET_TYPE_KD_DEBUG_IO = 3
PACKET_TYPE_KD_ACKNOWLEDGE = 4
PACKET_TYPE_KD_RESEND = 5
PACKET_TYPE_KD_RESET = 6
PACKET_TYPE_KD_STATE_CHANGE64 = 7
PACKET_TYPE_MAX = 8

PACKET_TYPE_TABLE = {
    PACKET_TYPE_UNUSED: "PACKET_TYPE_UNUSED",
    PACKET_TYPE_KD_STATE_CHANGE32: "PACKET_TYPE_KD_STATE_CHANGE32",
    PACKET_TYPE_KD_STATE_MANIPULATE: "PACKET_TYPE_KD_STATE_MANIPULATE",
    PACKET_TYPE_KD_DEBUG_IO: "PACKET_TYPE_KD_DEBUG_IO",
    PACKET_TYPE_KD_ACKNOWLEDGE: "PACKET_TYPE_KD_ACKNOWLEDGE",
    PACKET_TYPE_KD_RESEND: "PACKET_TYPE_KD_RESEND",
    PACKET_TYPE_KD_RESET: "PACKET_TYPE_KD_RESET",
    PACKET_TYPE_KD_STATE_CHANGE64: "PACKET_TYPE_KD_STATE_CHANGE64",
    PACKET_TYPE_MAX: "PACKET_TYPE_MAX",
}

# PACKET_TYPE_KD_DEBUG_IO apis
# DBGKD_DEBUG_IO
DbgKdPrintStringApi = 0x00003230
DbgKdGetStringApi = 0x00003231

# PACKET_TYPE_KD_STATE_CHANGE states
# X86_NT5_DBGKD_WAIT_STATE_CHANGE64
DbgKdExceptionStateChange = 0x00003030
DbgKdLoadSymbolsStateChange = 0x00003031

STATE_CHANGE_TABLE = {
    DbgKdExceptionStateChange: "DbgKdExceptionStateChange",
    DbgKdLoadSymbolsStateChange: "DbgKdLoadSymbolsStateChange",
}

# PACKET_TYPE_KD_STATE_MANIPULATE api numbers
# DBGKD_MANIPULATE_STATE64
DbgKdReadVirtualMemoryApi = 0x00003130
DbgKdWriteVirtualMemoryApi = 0x00003131
DbgKdGetContextApi = 0x00003132
DbgKdSetContextApi = 0x00003133
DbgKdWriteBreakPointApi = 0x00003134
DbgKdRestoreBreakPointApi = 0x00003135
DbgKdContinueApi = 0x00003136
DbgKdReadControlSpaceApi = 0x00003137
DbgKdWriteControlSpaceApi = 0x00003138
DbgKdReadIoSpaceApi = 0x00003139
DbgKdWriteIoSpaceApi = 0x0000313A
DbgKdRebootApi = 0x0000313B
DbgKdContinueApi2 = 0x0000313C
DbgKdReadPhysicalMemoryApi = 0x0000313D
DbgKdWritePhysicalMemoryApi = 0x0000313E
DbgKdSetSpecialCallApi = 0x00003140
DbgKdClearSpecialCallsApi = 0x00003141
DbgKdSetInternalBreakPointApi = 0x00003142
DbgKdGetInternalBreakPointApi = 0x00003143
DbgKdReadIoSpaceExtendedApi = 0x00003144
DbgKdWriteIoSpaceExtendedApi = 0x00003145
DbgKdGetVersionApi = 0x00003146
DbgKdWriteBreakPointExApi = 0x00003147
DbgKdRestoreBreakPointExApi = 0x00003148
DbgKdCauseBugCheckApi = 0x00003149
DbgKdSwitchProcessor = 0x00003150
DbgKdPageInApi = 0x00003151
DbgKdReadMachineSpecificRegister = 0x00003152
DbgKdWriteMachineSpecificRegister = 0x00003153
DbgKdSearchMemoryApi = 0x00003156
DbgKdGetBusDataApi = 0x00003157
DbgKdSetBusDataApi = 0x00003158
DbgKdCheckLowMemoryApi = 0x00003159

STATE_MANIPULATE_TABLE = {
    DbgKdReadVirtualMemoryApi: "DbgKdReadVirtualMemoryApi",
    DbgKdWriteVirtualMemoryApi: "DbgKdWriteVirtualMemoryApi",
    DbgKdGetContextApi: "DbgKdGetContextApi",
    DbgKdSetContextApi: "DbgKdSetContextApi",
    DbgKdWriteBreakPointApi: "DbgKdWriteBreakPointApi",
    DbgKdRestoreBreakPointApi: "DbgKdRestoreBreakPointApi",
    DbgKdContinueApi: "DbgKdContinueApi",
    DbgKdReadControlSpaceApi: "DbgKdReadControlSpaceApi",
    DbgKdWriteControlSpaceApi: "DbgKdWriteControlSpaceApi",
    DbgKdReadIoSpaceApi: "DbgKdReadIoSpaceApi",
    DbgKdWriteIoSpaceApi: "DbgKdWriteIoSpaceApi",
    DbgKdRebootApi: "DbgKdRebootApi",
    DbgKdContinueApi2: "DbgKdContinueApi2",
    DbgKdReadPhysicalMemoryApi: "DbgKdReadPhysicalMemoryApi",
    DbgKdWritePhysicalMemoryApi: "DbgKdWritePhysicalMemoryApi",
    DbgKdSetSpecialCallApi: "DbgKdSetSpecialCallApi",
    DbgKdClearSpecialCallsApi: "DbgKdClearSpecialCallsApi",
    DbgKdSetInternalBreakPointApi: "DbgKdSetInternalBreakPointApi",
    DbgKdGetInternalBreakPointApi: "DbgKdGetInternalBreakPointApi",
    DbgKdReadIoSpaceExtendedApi: "DbgKdReadIoSpaceExtendedApi",
    DbgKdWriteIoSpaceExtendedApi: "DbgKdWriteIoSpaceExtendedApi",
    DbgKdGetVersionApi: "DbgKdGetVersionApi",
    DbgKdWriteBreakPointExApi: "DbgKdWriteBreakPointExApi",
    DbgKdRestoreBreakPointExApi: "DbgKdRestoreBreakPointExApi",
    DbgKdCauseBugCheckApi: "DbgKdCauseBugCheckApi",
    DbgKdSwitchProcessor: "DbgKdSwitchProcessor",
    DbgKdPageInApi: "DbgKdPageInApi",
    DbgKdReadMachineSpecificRegister: "DbgKdReadMachineSpecificRegister",
    DbgKdWriteMachineSpecificRegister: "DbgKdWriteMachineSpecificRegister",
    DbgKdSearchMemoryApi: "DbgKdSearchMemoryApi",
    DbgKdGetBusDataApi: "DbgKdGetBusDataApi",
    DbgKdSetBusDataApi: "DbgKdSetBusDataApi",
    DbgKdCheckLowMemoryApi: "DbgKdCheckLowMemoryApi",
}


HRESULT_STATUS_SUCCESS = 0x00000000
HRESULT_STATUS_PENDING = 0x00000103
HRESULT_STATUS_UNSUCCESSFUL = 0xC0000001
HRESULT_DBG_EXCEPTION_HANDLED = 0x00010001
HRESULT_DBG_CONTINUE = 0x00010002
HRESULT_DBG_REPLY_LATER = 0x40010001
HRESULT_DBG_UNABLE_TO_PROVIDE_HANDLE = 0x40010002
HRESULT_DBG_TERMINATE_THREAD = 0x40010003
HRESULT_DBG_TERMINATE_PROCESS = 0x40010004
HRESULT_DBG_CONTROL_C = 0x40010005
HRESULT_DBG_PRINTEXCEPTION_C = 0x40010006
HRESULT_DBG_RIPEXCEPTION = 0x40010007
HRESULT_DBG_CONTROL_BREAK = 0x40010008
HRESULT_DBG_COMMAND_EXCEPTION = 0x40010009
HRESULT_DBG_EXCEPTION_NOT_HANDLED = 0x80010001
HRESULT_DBG_NO_STATE_CHANGE = 0xC0010001
HRESULT_DBG_APP_NOT_IDLE = 0xC0010002


STATE_CHANGE_EXCEPTIONS = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000002: "EXCEPTION_DATATYPE_MISALIGNMENT",
    0xC000008D: "EXCEPTION_FLT_DENORMAL_OPERAND",
    0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    0xC000008F: "EXCEPTION_FLT_INEXACT_RESULT",
    0xC0000030: "EXCEPTION_FLT_INVALID_OPERATION",
    0xC0000091: "EXCEPTION_FLT_OVERFLOW",
    0xC0000032: "EXCEPTION_FLT_STACK_CHECK",
    0xC0000033: "EXCEPTION_FLT_UNDERFLOW",
    0x80000001: "EXCEPTION_GUARD_PAGE",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000006: "EXCEPTION_IN_PAGE_ERROR",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC0000035: "EXCEPTION_INT_OVERFLOW",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
}
