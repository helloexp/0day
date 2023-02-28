2.测试FCKeditor上传点
=====================

一、漏洞简介
------------

二、影响范围
------------

三、复现过程
------------

    FCKeditor/editor/filemanager/browser/default/connectors/test.html
    FCKeditor/editor/filemanager/upload/test.html
    FCKeditor/editor/filemanager/connectors/test.html
    FCKeditor/editor/filemanager/connectors/uploadtest.html

    FCKeditor/_samples/default.html
    FCKeditor/_samples/asp/sample01.asp
    FCKeditor/_samples/asp/sample02.asp
    FCKeditor/_samples/asp/sample03.asp
    FCKeditor/_samples/asp/sample04.asp
    FCKeditor/_samples/default.html
    FCKeditor/editor/fckeditor.htm
    FCKeditor/editor/fckdialog.html

    FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector.jsp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
    FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/php/connector.php
    FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/asp/connector.asp
    FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/aspx/connector.aspx
    FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/jsp/connector.jsp

    FCKeditor/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp
    FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp
    fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/aspx/connector.Aspx
    fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/php/connector.php
