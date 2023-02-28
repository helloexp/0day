## 漏洞概述

VMware vCenter特定版本存在任意文件读取漏洞，攻击者通过构造特定的请求，可以读取服务器上任意文件

## 影响范围

```http
VMware vCenter Server 6.5.0a- f 版本
```

## POC


`targets.txt` 用于存放目标IP 或域名，然后直接运行此脚本即可 python vCenter-info-leak.py
漏洞验证成功的目标存放于`success.txt`，连接失败的错误信息存放于`error.txt`中