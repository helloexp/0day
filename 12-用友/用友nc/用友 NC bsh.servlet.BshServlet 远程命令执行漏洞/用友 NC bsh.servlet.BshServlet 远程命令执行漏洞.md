## 用友 NC bsh.servlet.BshServlet 远程命令执行漏洞

## 漏洞描述

用友 NC bsh.servlet.BshServlet 存在远程命令执行漏洞，通过BeanShell 执行远程命令获取服务器权限

## 漏洞影响

> 用友NC

## FOFA

> icon_hash="1085941792"

## 漏洞复现

首先访问如下页面：

![](/resource/用友NC远程命令执行/1.png)



漏洞URL为：

```
/servlet/~ic/bsh.servlet.BshServlet
```

![](/resource/用友NC远程命令执行/2.png)

在该界面只需要把print换成exec函数即可命令执行。