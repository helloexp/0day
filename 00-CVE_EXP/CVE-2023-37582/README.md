# CVE-2023-37582_EXPLOIT
Apache RocketMQ Arbitrary File Write Vulnerability Exploit Demo

# Overview
In fact, the Arbitrary file write vulnerability(CVE-2023-37582) in Apache RocketMQ has already been addressed in the CVE-2023-33246 RCE vulnerability. 
However, the fix provided for [CVE-2023-33246](https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT) RCE is not comprehensive as it only resolves the impact on RocketMQ's broker. 
This vulnerability affects RocketMQ's nameserver, and exploiting it allows for arbitrary file write capabilities.




# Setup local RocketMQ environment via Docker
```bash

# start name server
docker run -d --name rmqnamesrv -p 9876:9876 apache/rocketmq:4.9.6 sh mqnamesrv

# start broker
docker run -d --name rmqbroker \
  --link rmqnamesrv:namesrv \
  -e "NAMESRV_ADDR=namesrv:9876" \
  -p 10909:10909 \
  -p 10911:10911 \
  -p 10912:10912 \
  apache/rocketmq:4.9.6 sh mqbroker \
  -c /home/rocketmq/rocketmq-4.9.6/conf/broker.conf

```

# Exploit 

It is important to note that the exploit provided is for demonstration purposes only. 
The current exploit allows for the writing of a file to the nameserver's `/tmp/pwned` directory.
Modifying the content of the `body` variable allows for the exploitation of this vulnerability by writing an OpenSSH private key or adding a cronjob. 
However, it is crucial to remember that such activities are unauthorized and can lead to serious security breaches. 
It is strongly advised to refrain from engaging in any malicious activities and to prioritize responsible and ethical cybersecurity practices.

```
usage: CVE-2023-37582.py [-h] [-ip IP] [-p P]

RocketMQ Exploit

optional arguments:
  -h, --help  show this help message and exit
  -ip IP      Nameserver address
  -p P        Nameserver listen port
```

# References
[RocketMQ commit: Fix incorrect naming](https://github.com/apache/rocketmq/pull/6843/files)
