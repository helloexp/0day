# Tomcat 默认密码
### Tomcat支持在后台部署war文件，可以直接将webshell部署到web目录下
后台地址默认为 `http://ip/manager/html`

* Tomcat5默认配置了两个角色：tomcat、role1。其中帐号为both、tomcat、role1的默认密码都是tomcat。
* Tomcat6默认没有配置任何用户以及角色，没办法用默认帐号登录。
* Tomcat7默认有tomcat用户，密码为tomcat 拥有直接部署war文件的权限，可以直接上马
* Tomcat8中正常安装的情况下默认没有任何用户，且manager页面只允许本地IP访问


### 修复方案
Tomcat的用户配置文件tomcat-users.xml中进行修改
