# CVE-2021-21972
Proof of Concept Exploit for vCenter CVE-2021-21972

Research credit to: https://swarm.ptsecurity.com/unauth-rce-vmware/, http://noahblog.360.cn/vcenter-6-5-7-0-rce-lou-dong-fen-xi/

Tested on both Windows and Unix vCenter VCSA targets.


## Usage
To benignly check if the target is vulnerable just supply the --target <ip> argument.

To exploit provide the --file, --path, and --operating-system flags.
Write the file supplied in the --file argument to the location specified in the --path argument. 

## Windows Targets:
Tested by uploading the webshell cmdjsp.jsp to the /statsreport endpoint as indicated by PtSwarm. The webshell executes commands in the context of NT AUTHORITY/SYSTEM.

![WindowsExec](Windows-Exec.png)

![WindowsProof](CVE-2021-21972-Windows-Proof.png)

## Unix Targets:
The file will be written in the context of the vsphere-ui user.
If the target is vulnerable, but the exploit fails, it is likely that the vsphere-ui user does not have permissions to write to the specified path.

If writing the vsphere-ui user's SSH authorized_keys, when SSH'ing with the keys it was observed in some cases that the vsphere-ui user's password had expired and forced you to update it (which you cannot because no password is set).

![UnixProof](CVE-2021-21972-Unix-Proof.png)
