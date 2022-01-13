Discuz! X 3.4 admincp\_misc.php SQL注入漏洞
===========================================

一、漏洞简介
------------

由于是update型注入，我们在后台已经可以利用数据库备份获得数据，对本网站意义不大，但是有同mysql的其他网站，如果权限不严，跨库查询，搞定同mysql的其他网站。

二、漏洞影响
------------

Discuz! X 3.4

三、复现过程
------------

    https://www.0-sec.org/admin.php?action=misc&operation=censor

192540\_0de6824f\_5044043.png
