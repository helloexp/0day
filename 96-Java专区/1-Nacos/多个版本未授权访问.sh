
nacos 下面的文件中，嵌入了默认的secret.key
通过此key ，可以构造有效的jwt 文件，然后直接可以获取服务器的敏感信息

distribution/conf/application.properties
nacos.core.auth.plugin.nacos.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789

漏洞影响版本
0.1.0 <= Nacos <= 2.2.0.1

