## Apache-Tomcat-CVE-12615

* 漏洞本质Tomcat配置了可写（readonly=false），导致我们可以往服务器写文件

* 当 Tomcat 运行在 Windows 主机上，且启用了 HTTP PUT 请求方法`（例如，将 readonly 初始化参数由默认值设置为 false）`，攻击者将有可能可通过精心构造的攻击请求向服务器上传包含任意代码的 JSP 文件。之后，JSP 文件中的代码将能被服务器执行。

* 虽然Tomcat对文件后缀有一定检测（不能直接写jsp），但我们使用一些文件系统的特性`（如Linux下可用/ windows下空格）`来绕过了限制
