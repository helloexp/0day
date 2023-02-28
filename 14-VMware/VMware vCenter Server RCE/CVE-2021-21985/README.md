# VMware vCenter Server RCE

### CVE
CVE-2021-21985

### 使用方法
1. 替换成自己的IP和端口
```shell
nmap -p443 --script CVE-2021-21985.nse 1.1.1.1
```

2. 检测到漏洞的输入如下

```shell
-- 443/tcp open  https
-- | CVE-2021-21985:
-- |   VULNERABLE:
-- |   vCenter 6.5-7.0 RCE
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2021-21985
-- |       The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input
-- |       validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server.
-- |     Disclosure date: 2021-05-28
-- |     References:
-- |
```