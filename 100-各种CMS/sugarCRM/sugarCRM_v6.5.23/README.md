# sugarCRM反序列化漏洞(对象注入漏洞)绕过__wakeup 

### 影响版本 `SugarCRM <= 6.5.23 PHP5 < 5.6.25 PHP7 < 7.0.10`

### 修复建议：
	include/utils.php sugar_unserialize函数正则匹配修正为 /[oc]:[^:]*\d+:/i··
